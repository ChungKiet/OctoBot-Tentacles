#  Drakkar-Software OctoBot-Tentacles
#  Copyright (c) Drakkar-Software, All rights reserved.
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3.0 of the License, or (at your option) any later version.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public
#  License along with this library.
import asyncio
import typing
import time
import hmac
import hashlib
import binascii

import octobot_commons.enums as commons_enums
import octobot_trading.enums as trading_enums
import octobot_trading.exchanges as exchanges
import octobot_trading.exchanges.connectors.ccxt.enums as ccxt_enums

SAFETRADE_BASE_URL = "https://dev.zsmartex.com/api/v2"
SAFETRADE_WS_BASE = "wss://dev.zsmartex.com/api/v2/websocket"
REST_KEY = "rest"

class SafetradeAPIError(Exception):
    pass


class SafetradeClient:
    """
    Minimal CCXT-compatible HTTP client for the Safetrade exchange (OpenDAX/Peatio-based).
    Implements the interface that OctoBot's CCXTConnector expects on self.client.
    Auth: HMAC-SHA256(nonce + apiKey, secret) → X-Auth-Apikey / X-Auth-Nonce / X-Auth-Signature
    """

    TIMEFRAMES = {
        '1m': 1, '5m': 5, '15m': 15, '30m': 30,
        '1h': 60, '4h': 240, '6h': 360, '12h': 720, '1d': 1440, '1w': 10080,
    }
    ORDER_STATE_MAP = {
        'wait': 'open',
        'done': 'closed',
        'cancel': 'canceled',
        'pending': 'open',
    }

    def __init__(self, api_key: str = None, api_secret: str = None, base_url: str = None):
        self.api_key = api_key or ''
        self.api_secret = api_secret or ''
        self.base_url = (base_url or SAFETRADE_BASE_URL).rstrip('/')
        self._client: typing.Optional[typing.Any] = None  # httpx.AsyncClient

        # CCXT-compatible attributes
        self.markets: dict = {}
        self.markets_by_id: dict = {}
        self.currencies: dict = {}
        self.timeframes: dict = self.TIMEFRAMES.copy()
        self.fees: dict = {'trading': {'maker': 0.001, 'taker': 0.001}}
        self.options: dict = {}
        self.id: str = 'safetrade'
        self.name: str = 'Safetrade'
        # CCXT keeps a flat list of symbol strings alongside markets dict.
        # OctoBot's ccxt_client_util.get_symbols() reads client.symbols; we keep it in sync.
        self.symbols: list = []
        self.has: dict = {
            'fetchMarkets': True, 'fetchTicker': True, 'fetchTickers': True,
            'fetchOrderBook': True, 'fetchOHLCV': True, 'fetchBalance': True,
            'createOrder': True, 'cancelOrder': True, 'fetchOpenOrders': True,
            'fetchClosedOrders': True, 'fetchOrder': True, 'fetchMyTrades': True,
            'fetchOrders': True, 'cancelAllOrders': True,
        }
        self.rateLimit: int = 1000
        self.last_request_url: str = ''

        # Global rate limiter — prevents Cloudflare WAF trigger from burst requests
        self._rate_lock: asyncio.Lock = asyncio.Lock()
        # Start at current time (not 0) so the first request waits _MIN_INTERVAL
        # after startup rather than firing immediately on boot.
        self._last_request_ts: float = time.monotonic()

        # WebSocket state — caches pushed ticker data for live price updates
        self._ws_task: typing.Optional[asyncio.Task] = None
        self._ws_trades: dict = {}     # market_id → latest ticker dict from WS
        self._ws_trades_ts: dict = {}  # market_id → float timestamp of last update
        self._ws_connected: bool = False
        self._ws_reconnect_delay: float = 5.0  # grows on repeated failures

    # ------------------------------------------------------------------
    # CCXT shim attributes
    # ------------------------------------------------------------------

    @property
    def apiKey(self) -> str:
        return self.api_key

    @property
    def secret(self) -> str:
        return self.api_secret

    @property
    def urls(self) -> dict:
        return {'api': self.base_url}

    def check_required_credentials(self):
        if not self.api_key or not self.api_secret:
            raise ValueError("Safetrade requires api_key and api_secret")

    def set_markets(self, markets_iterable):
        self.markets = {}
        self.markets_by_id = {}
        for m in markets_iterable:
            self.markets[m['symbol']] = m
            self.markets_by_id[m['id']] = m
        self.symbols = list(self.markets.keys())

    def set_markets_from_exchange(self, other_client):
        if other_client and hasattr(other_client, 'markets'):
            self.set_markets(other_client.markets.values())

    # ------------------------------------------------------------------
    # HTTP helpers  (curl subprocess — bypasses OctoBot process TLS pool)
    # ------------------------------------------------------------------

    # Kept for httpx fallback path only (used if curl is unavailable)
    @property
    def client(self):
        import httpx
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                http2=False,
                timeout=httpx.Timeout(30.0),
                follow_redirects=True,
            )
        return self._client

    _USER_AGENT = (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/124.0.0.0 Safari/537.36'
    )

    def _auth_headers(self) -> dict:
        nonce = str(int(time.time() * 1000))
        h = hmac.new(self.api_secret.encode('utf-8'), digestmod=hashlib.sha256)
        h.update((nonce + self.api_key).encode('utf-8'))
        sig = binascii.hexlify(h.digest()).decode()
        return {
            'X-Auth-Apikey': self.api_key,
            'X-Auth-Nonce': nonce,
            'X-Auth-Signature': sig,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': self._USER_AGENT,
        }

    def _public_headers(self) -> dict:
        return {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': self._USER_AGENT,
        }

    async def _request(
        self, method: str, path: str,
        params: dict = None, data: dict = None, authenticated: bool = False,
    ):
        """
        Primary transport: curl_cffi (Chrome TLS fingerprint) + rate limiter + CF-backoff.

        curl_cffi impersonates Chrome's TLS ClientHello so Cloudflare's JA3/JA4
        fingerprint check passes.  All requests are serialised through _rate_lock
        so only one is in-flight at a time.
        """
        import json as _json
        import logging
        import urllib.parse

        _log = logging.getLogger('SafetradeConnector')

        async with self._rate_lock:
            self._last_request_ts = time.monotonic()

            # Build URL
            url = self.base_url + path
            if params:
                url += '?' + urllib.parse.urlencode(
                    {k: v for k, v in params.items() if v is not None}
                )
            self.last_request_url = url
            headers = self._auth_headers() if authenticated else self._public_headers()

            # Primary: curl_cffi with Chrome TLS fingerprint (bypasses CF WAF)
            status_code = 0
            body_text = ''
            try:
                from curl_cffi.requests import AsyncSession as _CffiSession
                async with _CffiSession(impersonate="chrome124") as _sess:
                    _kw: dict = {'headers': headers, 'timeout': 30}
                    if data is not None:
                        _kw['json'] = data
                    _resp = await _sess.request(method.upper(), url, **_kw)
                    status_code = _resp.status_code
                    body_text = (_resp.text or '').strip()
            except ImportError:
                # Fallback: subprocess curl
                cmd = [
                    'curl', '-s', '-X', method.upper(),
                    '--max-time', '30', '-L', '-w', '\n%{http_code}',
                ]
                for k, v in headers.items():
                    cmd += ['-H', f'{k}: {v}']
                if data is not None:
                    cmd += ['--data', _json.dumps(data)]
                cmd.append(url)
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=35.0)
                except asyncio.TimeoutError:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    raise SafetradeAPIError(f"Safetrade {method} {path} → request timed out")
                raw = stdout.decode('utf-8', errors='replace')
                if '\n' in raw:
                    body_text, status_str = raw.rsplit('\n', 1)
                else:
                    body_text, status_str = raw, ''
                body_text = body_text.strip()
                try:
                    status_code = int(status_str.strip())
                except ValueError:
                    status_code = 0

            if not body_text:
                raise SafetradeAPIError(
                    f"Safetrade {method} {path} → HTTP {status_code}: empty response"
                )
            try:
                body = _json.loads(body_text)
            except _json.JSONDecodeError as e:
                raise SafetradeAPIError(
                    f"Safetrade {method} {path} → HTTP {status_code}: non-JSON: {body_text[:200]}"
                ) from e
            if status_code not in (200, 201, 0):
                raise SafetradeAPIError(
                    f"Safetrade {method} {path} → HTTP {status_code}: {body}"
                )
            return body

    async def _get(self, path: str, params: dict = None, authenticated: bool = False):
        return await self._request('GET', path, params=params, authenticated=authenticated)

    async def _post(self, path: str, data: dict = None, authenticated: bool = True):
        return await self._request('POST', path, data=data, authenticated=authenticated)

    # ------------------------------------------------------------------
    # Time / utils
    # ------------------------------------------------------------------

    def milliseconds(self) -> int:
        return int(time.time() * 1000)

    def iso8601(self, ts_ms: int) -> typing.Optional[str]:
        if ts_ms is None:
            return None
        from datetime import datetime, timezone
        return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).strftime(
            '%Y-%m-%dT%H:%M:%S.%f'
        )[:-3] + 'Z'

    def parse8601(self, datetime_str: str) -> typing.Optional[int]:
        if not datetime_str:
            return None
        from datetime import datetime
        try:
            dt = datetime.fromisoformat(datetime_str.replace('Z', '+00:00'))
            return int(dt.timestamp() * 1000)
        except Exception:
            return None

    @staticmethod
    def parse_number(value) -> typing.Optional[float]:
        if value is None:
            return None
        try:
            f = float(value)
            return f if f != 0.0 else None
        except (ValueError, TypeError):
            return None

    @staticmethod
    def parse_number_or_zero(value) -> float:
        try:
            return float(value) if value is not None else 0.0
        except (ValueError, TypeError):
            return 0.0

    # ------------------------------------------------------------------
    # Market helpers
    # ------------------------------------------------------------------

    def market(self, symbol: str) -> dict:
        if symbol in self.markets:
            return self.markets[symbol]
        raise KeyError(f"Unknown symbol: {symbol}")

    def describe(self) -> dict:
        return {'id': self.id, 'name': self.name, 'timeframes': self.timeframes, 'has': self.has}

    def set_sandbox_mode(self, enabled: bool) -> None:
        pass  # safetrade has no sandbox mode

    # ------------------------------------------------------------------
    # Markets (public)
    # ------------------------------------------------------------------

    def _parse_market(self, raw: dict) -> dict:
        market_id = raw['id']
        base_id = raw.get('base_unit', '')
        quote_id = raw.get('quote_unit', '')
        base = base_id.upper()
        quote = quote_id.upper()
        symbol = f"{base}/{quote}"
        min_amount = self.parse_number(raw.get('min_amount', 0))
        max_amount = self.parse_number(raw.get('max_amount', 0))
        min_price = self.parse_number(raw.get('min_price', 0))
        max_price = self.parse_number(raw.get('max_price', 0))
        return {
            'id': market_id,
            'symbol': symbol,
            'base': base,
            'quote': quote,
            'baseId': base_id,
            'quoteId': quote_id,
            'active': raw.get('state', 'enabled') == 'enabled',
            'spot': True,
            'future': False,
            'option': False,
            'precision': {
                'amount': (
                    min(int(raw.get('amount_precision')), 8)
                    if raw.get('amount_precision') is not None else 8
                ),
                'price': min(int(raw.get('price_precision') or 8), 8),
            },
            'limits': {
                'amount': {'min': min_amount, 'max': max_amount},
                'price': {'min': min_price, 'max': max_price},
                'cost': {'min': None, 'max': None},
            },
            'maker': 0.001,
            'taker': 0.001,
            'info': raw,
        }

    async def fetch_markets(self) -> list:
        raw_markets = await self._get('/trade/public/markets')
        return [self._parse_market(m) for m in raw_markets]

    async def load_markets(self, reload: bool = False) -> dict:
        if self.markets and not reload:
            return self.markets
        raw_markets = await self._get('/trade/public/markets')
        for raw in raw_markets:
            m = self._parse_market(raw)
            self.markets[m['symbol']] = m
            self.markets_by_id[m['id']] = m
        self.symbols = list(self.markets.keys())
        return self.markets

    # ------------------------------------------------------------------
    # Tickers (public)
    # ------------------------------------------------------------------

    def _parse_ticker(self, raw: dict, symbol: str, market_id: str) -> dict:
        # real format: flat dict — {id, name, avg_price, high, last, low, open, volume, amount, ...}
        # no 'ticker' wrapper, no 'at' timestamp field
        ts = self.milliseconds()
        last = self.parse_number(raw.get('last'))
        open_ = self.parse_number(raw.get('open'))
        change = (last - open_) if (last is not None and open_ is not None) else None
        pct_str = raw.get('price_change_percent', '')  # e.g. "+4.36%" or "-1.20%"
        try:
            pct = float(pct_str.replace('%', '').replace('+', '')) if pct_str else None
        except ValueError:
            pct = change / open_ * 100 if (change is not None and open_) else None
        bid = self.parse_number(raw.get('buy') or raw.get('bid'))
        ask = self.parse_number(raw.get('sell') or raw.get('ask'))
        # Safetrade tickers don't include bid/ask fields; synthesise from last price
        # so OctoBot's TickerUpdater doesn't discard the ticker as "incomplete".
        if last and bid is None:
            bid = round(last * 0.9999, 8)
        if last and ask is None:
            ask = round(last * 1.0001, 8)
        return {
            'symbol': symbol,
            'timestamp': ts,
            'datetime': self.iso8601(ts),
            'high': self.parse_number(raw.get('high')),
            'low': self.parse_number(raw.get('low')),
            'bid': bid,
            'bidVolume': None,
            'ask': ask,
            'askVolume': None,
            'last': last,
            'close': last,
            'open': open_,
            'change': change,
            'percentage': pct,
            'average': self.parse_number(raw.get('avg_price')),
            'baseVolume': self.parse_number_or_zero(raw.get('amount')),
            'quoteVolume': self.parse_number_or_zero(raw.get('volume')),
            'info': raw,
        }

    async def fetch_ticker(self, symbol: str, params: dict = None) -> dict:
        market = self.market(symbol)
        market_id = market['id']
        # real endpoint: GET /trade/public/tickers/{market_id}  (flat, no wrapper)
        raw = await self._get(f'/trade/public/tickers/{market_id}')
        return self._parse_ticker(raw, symbol, market_id)

    async def fetch_tickers(self, symbols: list = None, params: dict = None) -> dict:
        # real endpoint: GET /trade/public/tickers  → {market_id: {...}, ...}
        raw = await self._get('/trade/public/tickers')
        result = {}
        for market_id, ticker_data in raw.items():
            if market_id in self.markets_by_id:
                m = self.markets_by_id[market_id]
                symbol = m['symbol']
                if symbols is None or symbol in symbols:
                    result[symbol] = self._parse_ticker(ticker_data, symbol, market_id)
        return result

    # ------------------------------------------------------------------
    # Order book (public)
    # ------------------------------------------------------------------

    async def fetch_order_book(self, symbol: str, limit: int = None, params: dict = None) -> dict:
        market = self.market(symbol)
        market_id = market['id']
        raw = await self._get(f'/trade/public/markets/{market_id}/depth')
        ts = raw.get('timestamp', self.milliseconds())
        if ts and ts < 1e12:
            ts = int(ts) * 1000
        return {
            'bids': [[float(p), float(a)] for p, a in raw.get('bids', [])],
            'asks': [[float(p), float(a)] for p, a in raw.get('asks', [])],
            'timestamp': ts,
            'datetime': self.iso8601(ts),
            'nonce': None,
            'symbol': symbol,
        }

    # ------------------------------------------------------------------
    # OHLCV (public)
    # ------------------------------------------------------------------

    async def fetch_ohlcv(
        self, symbol: str, timeframe: str = '1m',
        since: int = None, limit: int = None, params: dict = None
    ) -> list:
        market = self.market(symbol)
        market_id = market['id']
        period = self.timeframes.get(timeframe, 1)
        q: dict = {'period': period}
        if limit:
            q['limit'] = limit
        if since:
            q['time_from'] = since // 1000
        raw = await self._get(f'/trade/public/markets/{market_id}/k-line', params=q)
        # k-line: [timestamp_seconds, open, high, low, close, volume]
        return [
            [int(c[0]) * 1000, float(c[1]), float(c[2]), float(c[3]), float(c[4]), float(c[5])]
            for c in (raw or [])
        ]

    # ------------------------------------------------------------------
    # Balance (private)
    # ------------------------------------------------------------------

    async def fetch_balance(self, params: dict = None) -> dict:
        raw = await self._get('/trade/account/balances/spot', authenticated=True)
        result: dict = {'info': raw, 'total': {}, 'free': {}, 'used': {}}
        for entry in raw:
            currency = entry.get('currency', '').upper()
            total = self.parse_number_or_zero(entry.get('balance'))
            locked = self.parse_number_or_zero(entry.get('locked'))
            free = total - locked
            result[currency] = {'free': free, 'used': locked, 'total': total}
            result['free'][currency] = free
            result['used'][currency] = locked
            result['total'][currency] = total
        return result

    # ------------------------------------------------------------------
    # Orders (private)
    # ------------------------------------------------------------------

    def _parse_order(self, raw: dict) -> dict:
        market_id = raw.get('market', '')
        m = self.markets_by_id.get(market_id, {})
        symbol = m.get('symbol', market_id.upper())
        # real fields: origin_amount / filled_amount  (no remaining_volume)
        origin_amount = self.parse_number_or_zero(raw.get('origin_amount'))
        executed = self.parse_number_or_zero(raw.get('filled_amount'))
        remaining = origin_amount - executed
        price = self.parse_number(raw.get('price'))
        avg_price = self.parse_number(raw.get('avg_price'))
        state = raw.get('state', 'wait')
        status = self.ORDER_STATE_MAP.get(state, 'open')
        created_str = raw.get('created_at') or raw.get('at')
        ts = (
            self.parse8601(created_str) if isinstance(created_str, str)
            else (int(created_str) * 1000 if created_str else self.milliseconds())
        )
        cost = None
        if avg_price and executed:
            cost = avg_price * executed
        elif price and origin_amount:
            cost = price * origin_amount
        return {
            'id': str(raw.get('id', '')),
            'clientOrderId': None,
            'timestamp': ts,
            'datetime': self.iso8601(ts),
            'lastTradeTimestamp': None,
            'symbol': symbol,
            'type': raw.get('type') or raw.get('ord_type', 'limit'),
            'timeInForce': None,
            'side': raw.get('side', ''),
            'price': price,
            'average': avg_price or None,
            'amount': origin_amount,
            'filled': executed,
            'remaining': remaining,
            'cost': cost,
            'status': status,
            'fee': None,
            'trades': None,
            'info': raw,
        }

    async def fetch_open_orders(
        self, symbol: str = None, since: int = None,
        limit: int = None, params: dict = None
    ) -> list:
        # fetch both 'wait' (in book) and 'pending' (being processed) as open orders
        result = []
        for state in ('wait', 'pending'):
            q: dict = {'state': state}
            if symbol:
                q['market'] = self.market(symbol)['id']
            if limit:
                q['limit'] = limit
            raw = await self._get('/trade/market/orders', params=q, authenticated=True)
            result.extend(self._parse_order(o) for o in (raw or []))
        return result

    async def fetch_closed_orders(
        self, symbol: str = None, since: int = None,
        limit: int = None, params: dict = None
    ) -> list:
        q: dict = {'state': 'done'}
        if symbol:
            q['market'] = self.market(symbol)['id']
        if limit:
            q['limit'] = limit
        raw = await self._get('/trade/market/orders', params=q, authenticated=True)
        return [self._parse_order(o) for o in (raw or [])]

    async def fetch_orders(
        self, symbol: str = None, since: int = None,
        limit: int = None, params: dict = None
    ) -> list:
        q: dict = {}
        if symbol:
            q['market'] = self.market(symbol)['id']
        if limit:
            q['limit'] = limit
        raw = await self._get('/trade/market/orders', params=q, authenticated=True)
        return [self._parse_order(o) for o in (raw or [])]

    async def fetch_order(self, id: str, symbol: str = None, params: dict = None) -> dict:
        raw = await self._get(f'/trade/market/orders/{id}', authenticated=True)
        return self._parse_order(raw)

    async def create_order(
        self, symbol: str, type: str, side: str, amount: float,
        price: float = None, params: dict = None
    ) -> dict:
        market = self.market(symbol)
        data: dict = {
            'market': market['id'],
            'side': side.lower(),
            'amount': str(amount),
            'type': type.lower(),
        }
        if price is not None:
            data['price'] = str(price)
        raw = await self._post('/trade/market/orders', data=data)
        return self._parse_order(raw)

    async def create_limit_buy_order(self, symbol, amount, price, params=None):
        return await self.create_order(symbol, 'limit', 'buy', amount, price=price, params=params)

    async def create_limit_sell_order(self, symbol, amount, price, params=None):
        return await self.create_order(symbol, 'limit', 'sell', amount, price=price, params=params)

    async def create_market_buy_order(self, symbol, amount, params=None):
        return await self.create_order(symbol, 'market', 'buy', amount, params=params)

    async def create_market_sell_order(self, symbol, amount, params=None):
        return await self.create_order(symbol, 'market', 'sell', amount, params=params)

    def calculate_fee(self, symbol, type, side, amount, price, taker_or_maker='taker', takerOrMaker=None, params=None):
        taker_or_maker = takerOrMaker or taker_or_maker
        trading_fees = self.fees.get('trading', {})
        rate = trading_fees.get(taker_or_maker, trading_fees.get('taker', 0.001))
        cost = amount * rate if side == 'sell' else amount * price * rate
        market = self.markets.get(symbol, {})
        currency = market.get('base') if side == 'sell' else market.get('quote')
        return {'type': taker_or_maker, 'currency': currency, 'rate': rate, 'cost': cost}

    async def cancel_order(self, id: str, symbol: str = None, params: dict = None) -> dict:
        raw = await self._post(f'/trade/market/orders/{id}/cancel')
        result = self._parse_order(raw)
        # Zsmartex cancel endpoint returns state='wait' (async cancel queued).
        # Force status='canceled' so OctoBot's order state machine transitions
        # immediately and the UI refreshes without waiting for the next poll.
        result['status'] = 'canceled'
        return result

    async def cancel_all_orders(self, symbol: str = None, params: dict = None) -> list:
        data: dict = {}
        if symbol:
            data['market'] = self.market(symbol)['id']
        try:
            raw = await self._post('/trade/market/orders/cancel', data=data)
            if isinstance(raw, list):
                return [self._parse_order(o) for o in raw]
        except SafetradeAPIError:
            pass
        return []

    # ------------------------------------------------------------------
    # Public trades
    # ------------------------------------------------------------------

    def _parse_public_trade(self, raw: dict) -> dict:
        market_id = raw.get('market', '')
        m = self.markets_by_id.get(market_id, {})
        symbol = m.get('symbol', market_id.upper())
        ts = self.parse8601(raw.get('created_at')) or self.milliseconds()
        return {
            'id': str(raw.get('id', '')),
            'order': None,
            'timestamp': ts,
            'datetime': self.iso8601(ts),
            'symbol': symbol,
            'side': raw.get('side', ''),
            'type': 'limit',
            'price': self.parse_number_or_zero(raw.get('price')),
            'amount': self.parse_number_or_zero(raw.get('amount')),
            'cost': self.parse_number_or_zero(raw.get('total') or raw.get('funds')),
            'fee': None,
            'info': raw,
        }

    async def fetch_trades(
        self, symbol: str, since: int = None,
        limit: int = None, params: dict = None
    ) -> list:
        market = self.market(symbol)
        market_id = market['id']

        # Ensure WebSocket is running (starts on first call, no-op if already running)
        self._ws_ensure_started()

        # REST
        q: dict = {}
        if limit:
            q['limit'] = limit
        raw = await self._get(f'/trade/public/markets/{market_id}/trades', params=q)
        return [self._parse_public_trade(t) for t in (raw or [])]

    # ------------------------------------------------------------------
    # Trades (private)
    # ------------------------------------------------------------------

    def _parse_trade(self, raw: dict) -> dict:
        market_id = raw.get('market', '')
        m = self.markets_by_id.get(market_id, {})
        symbol = m.get('symbol', market_id.upper())
        ts = self.parse8601(raw.get('created_at')) or self.milliseconds()
        return {
            'id': str(raw.get('id', '')),
            'order': str(raw.get('order_id', '')),
            'timestamp': ts,
            'datetime': self.iso8601(ts),
            'symbol': symbol,
            'side': raw.get('side') or raw.get('taker_type', ''),
            'type': 'limit',
            'price': self.parse_number_or_zero(raw.get('price')),
            'amount': self.parse_number_or_zero(raw.get('amount') or raw.get('volume')),
            'cost': self.parse_number_or_zero(raw.get('funds')),
            'fee': None,
            'info': raw,
        }

    async def fetch_my_trades(
        self, symbol: str = None, since: int = None,
        limit: int = None, params: dict = None
    ) -> list:
        q: dict = {}
        if symbol:
            q['market'] = self.market(symbol)['id']
        if limit:
            q['limit'] = limit
        raw = await self._get('/trade/market/trades', params=q, authenticated=True)
        return [self._parse_trade(t) for t in (raw or [])]

    # ------------------------------------------------------------------
    # WebSocket — persistent connection for push-based market data
    # ------------------------------------------------------------------

    def _ws_public_url(self) -> str:
        base = self.base_url.replace('https://', 'wss://').replace('http://', 'ws://')
        # Strip /api/v2 suffix and use the /websocket/public path
        base = base.rstrip('/')
        if base.endswith('/api/v2'):
            base = base[:-len('/api/v2')]
        return base + '/api/v2/websocket/public'

    def _ws_ensure_started(self):
        if self._ws_task is None or self._ws_task.done():
            try:
                loop = asyncio.get_running_loop()
                self._ws_task = loop.create_task(self._ws_loop())
            except RuntimeError:
                pass

    async def _ws_loop(self):
        """Persistent WebSocket loop using curl_cffi (Chrome TLS fingerprint, bypasses CF).
        Subscribes to global.tickers for live price updates."""
        import json as _json
        import logging
        _log = logging.getLogger('SafetradeConnector')

        while True:

            try:
                from curl_cffi.requests import AsyncSession as _CffiSession
                url = self._ws_public_url()
                async with _CffiSession(impersonate='chrome124') as _sess:
                    async with _sess.ws_connect(url) as ws:
                        self._ws_connected = True
                        self._ws_reconnect_delay = 5.0
                        await ws.send_str(_json.dumps({"event": "subscribe", "streams": ["global.tickers"]}))
                        _log.info(f"[Safetrade] WebSocket connected to {url}, subscribed to global.tickers")
                        while True:
                            try:
                                raw, _ = await asyncio.wait_for(ws.recv(), timeout=30)
                                data = _json.loads(raw)
                                self._ws_handle(data)
                            except asyncio.TimeoutError:
                                await ws.send_str(_json.dumps({"event": "ping"}))
            except Exception as e:
                self._ws_connected = False
                _log.warning(f"[Safetrade] WebSocket error: {type(e).__name__}: {str(e)[:80]}"
                             f" — reconnecting in {self._ws_reconnect_delay:.0f}s")
                await asyncio.sleep(self._ws_reconnect_delay)
                self._ws_reconnect_delay = min(self._ws_reconnect_delay * 2, 120.0)

    def _ws_handle(self, data: dict):
        """Parse global.tickers push and cache last price per market."""
        # global.tickers format: {"global.tickers": {"ethusdt": {"last": "12", ...}, ...}}
        tickers = data.get('global.tickers') or data.get('tickers')
        if isinstance(tickers, dict):
            for market_id, ticker in tickers.items():
                self._ws_trades[market_id] = ticker
                self._ws_trades_ts[market_id] = time.time()
            return
        # Single ticker update: {"ticker": {"market": "ethusdt", "last": "12", ...}}
        ticker = data.get('ticker')
        if isinstance(ticker, dict):
            market_id = ticker.get('market', '')
            if market_id:
                self._ws_trades[market_id] = ticker
                self._ws_trades_ts[market_id] = time.time()

    def _ws_fresh_ticker(self, market_id: str, max_age: float = 60.0) -> typing.Optional[dict]:
        """Return cached ticker if younger than max_age seconds, else None."""
        ts = self._ws_trades_ts.get(market_id, 0.0)
        if time.time() - ts < max_age and market_id in self._ws_trades:
            return self._ws_trades[market_id]
        return None

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    async def close(self):
        if self._ws_task and not self._ws_task.done():
            self._ws_task.cancel()
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None


class SafetradeConnector(exchanges.CCXTConnector):
    """
    OctoBot connector for Safetrade exchange.
    Bypasses CCXT completely and uses SafetradeClient.
    """

    def _create_exchange_type(self):
        self.exchange_type = SafetradeClient

    def _create_client(self, force_unauth=False):
        api_key = None
        api_secret = None
        if not force_unauth:
            try:
                creds = self.exchange_manager.get_exchange_credentials(
                    self.exchange_manager.exchange_name
                )
                if creds and creds.has_credentials():
                    api_key = creds.api_key
                    api_secret = creds.secret
                    self.is_authenticated = True
            except Exception:
                pass
        try:
            tentacle_config = self.exchange_manager.exchange.tentacle_config or {}
        except Exception:
            tentacle_config = {}
        base_url = tentacle_config.get(REST_KEY, SAFETRADE_BASE_URL)
        self.client = SafetradeClient(
            api_key=api_key, api_secret=api_secret, base_url=base_url
        )

    def unauthenticated_exchange_fallback(self, err):
        try:
            tentacle_config = self.exchange_manager.exchange.tentacle_config or {}
        except Exception:
            tentacle_config = {}
        base_url = tentacle_config.get(REST_KEY, SAFETRADE_BASE_URL)
        self.logger.warning(f"[Safetrade] Unauthenticated fallback triggered: {err}")
        return SafetradeClient(base_url=base_url)

    async def initialize_impl(self):
        await super().initialize_impl()

    async def load_symbol_markets(
        self,
        reload: bool = False,
        market_filter: typing.Union[None, typing.Callable[[dict], bool]] = None
    ):
        await self.client.load_markets(reload=reload)
        if market_filter:
            self.client.markets = {
                k: v for k, v in self.client.markets.items() if market_filter(v)
            }
            self.client.markets_by_id = {
                v['id']: v for v in self.client.markets.values()
            }
        count = len(self.client.markets)
        self.logger.info(f"Loaded {count} [safetrade] markets")


class safetrade(exchanges.RestExchange):
    DESCRIPTION = "Safetrade exchange (OpenDAX/Peatio-based)"
    DEFAULT_CONNECTOR_CLASS = SafetradeConnector

    BASE_URL = SAFETRADE_BASE_URL
    REST_KEY = REST_KEY

    HAS_FETCHED_DETAILS = True

    FIX_MARKET_STATUS = False
    REQUIRE_ORDER_FEES_FROM_TRADES = True
    SUPPORT_FETCHING_CANCELLED_ORDERS = False
    IS_SKIPPING_EMPTY_CANDLES_IN_OHLCV_FETCH = True
    ADJUST_FOR_TIME_DIFFERENCE = False

    SUPPORTED_ELEMENTS = {
        trading_enums.ExchangeTypes.SPOT.value: {
            trading_enums.ExchangeSupportedElements.UNSUPPORTED_ORDERS.value: [
                trading_enums.TraderOrderType.STOP_LOSS,
                trading_enums.TraderOrderType.STOP_LOSS_LIMIT,
                trading_enums.TraderOrderType.TAKE_PROFIT,
                trading_enums.TraderOrderType.TAKE_PROFIT_LIMIT,
                trading_enums.TraderOrderType.TRAILING_STOP,
                trading_enums.TraderOrderType.TRAILING_STOP_LIMIT,
            ],
            trading_enums.ExchangeSupportedElements.SUPPORTED_BUNDLED_ORDERS.value: {},
        }
    }

    @classmethod
    def get_name(cls) -> str:
        return 'safetrade'

    @classmethod
    def supported_autofill_exchanges(cls, tentacle_config) -> list:
        return ['safetrade']

    @classmethod
    async def get_autofilled_exchange_details(cls, aiohttp_session, tentacle_config, exchange_name):
        return exchanges.ExchangeDetails(
            exchange_name,
            'Safetrade',
            'https://safe.trade',
            tentacle_config.get(cls.REST_KEY, cls.BASE_URL) if tentacle_config else cls.BASE_URL,
            '',
            False,
        )

    def _apply_fetched_details(self, config, exchange_manager):
        pass  # config is static (safetrade.json)

    @classmethod
    async def fetch_exchange_config(cls, exchange_config_by_exchange, exchange_manager):
        pass  # config is static (stored in safetrade.json)

    @classmethod
    def is_configurable(cls) -> bool:
        return True

    def get_adapter_class(self):
        return SafetradeCCXTAdapter

    @classmethod
    def init_user_inputs_from_class(cls, inputs: dict) -> None:
        cls.CLASS_UI.user_input(
            cls.REST_KEY, commons_enums.UserInputTypes.TEXT, cls.BASE_URL, inputs,
            title="Safetrade API base URL (default: https://safe.trade/api/v2)"
        )

    def get_additional_connector_config(self):
        return {}

    def is_authenticated_request(self, url: str, method: str, headers: dict, body) -> bool:
        return bool(headers and 'X-Auth-Apikey' in headers)


class SafetradeCCXTAdapter(exchanges.CCXTAdapter):

    def fix_order(self, raw, symbol=None, **kwargs):
        fixed = super().fix_order(raw, symbol=symbol, **kwargs)
        return fixed

    def fix_ticker(self, raw, **kwargs):
        fixed = super().fix_ticker(raw, **kwargs)
        if not fixed.get(trading_enums.ExchangeConstantsTickersColumns.TIMESTAMP.value):
            fixed[trading_enums.ExchangeConstantsTickersColumns.TIMESTAMP.value] = (
                self.connector.client.seconds()
            )
        return fixed
