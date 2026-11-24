# -*- coding: utf-8 -*-
# @name 河豚 4K（筛选版）
# @description OmniBox Python 爬虫源：河豚 4K 采集接口（protobuf + RSA/AES 签名），带分类筛选、线路排序
# @version 1.0.0
# @indexs 1
# @dependencies: requests,pycryptodome
#
# 注释属性说明（官方仅解析 @version / @downloadURL / @indexs / @push / @dependencies，且须在前 50 行内）：
#   - 本脚本为本地改写稿，尚未落仓分发，故暂不写 @downloadURL；
#     落仓后请补 @downloadURL 指向 main 分支原始文件地址，并同步升级 @version。
#   - requests / pycryptodome 由后台依据 @dependencies 自动安装。
#
# 为什么接口请求不使用 OmniBox.request：
#   源站接口是 application/x-protobuf 二进制请求/响应，并依赖 RSA/AES 自定义请求头签名；
#   官方 SDK 的 request(url, options) 中 body 为 str|dict、返回 body 为 str，无法保真传输二进制，
#   因此底层网络仍走 requests.Session，SDK 只用于 log / 缓存 / run 注册（Python 运行时支持第三方库）。
#
# 环境变量（站点专有配置，不与通用 SITE_API 冲突）：
#   SITE_API        接口域名或配置文件地址（覆盖 host）
#   HT_CONFIG_JSON  完整 JSON 配置，可覆盖 CONFIG 任意键
#   HT_EXTEND       兼容旧版 extend：URL$配置键 / JSON 字符串 / 纯 host
#   HT_PUBLIC_KEY / HT_SAFE_CODE / HT_DATA_IV / HT_PKG / HT_VNAME   覆盖加密与设备参数
#   HT_FROM         线路排序@屏蔽（与旧版 from 同格式）
#   HT_LINE_ORDER / HT_LINE_BLOCK   逗号分隔，单独覆盖排序 / 屏蔽关键词

import asyncio
import base64
import json
import os
import random
import re
import time
import uuid
from urllib.parse import quote, unquote

try:
    import requests
except Exception:
    requests = None

try:
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.PublicKey import RSA
    from Crypto.Util.Padding import pad, unpad
except Exception:
    AES = PKCS1_v1_5 = RSA = None

# SDK 由运行器通过 PYTHONPATH 注入；fallback 仅供本地调试 / 单元测试
try:
    from spider_runner import OmniBox, run
except Exception:
    class _LocalOmniBox(object):
        async def log(self, level, message):
            print("[%s] %s" % (level, message))

        async def getCache(self, key):
            return None

        async def setCache(self, key, value, exSeconds=None):
            return True

    OmniBox = _LocalOmniBox()

    def run(handlers):
        print("[local] 已注册 handler: %s" % ", ".join(handlers or {}))


CONFIG = {
    "appName": "河豚",
    "publicKey": "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCr8SzZhjYy+rsya1K09t8d2K50pWFoBkgUqMpKOiW+3IEVKd4eTdvg9RSOjQ82kypL6R9BnsmrS1V8s4PVDwjQbUtYhTPPC9Hz16qY7rpD6m0d2vr09/UpWQ5uOy9PR0QTrsioveZ+DIe9jc3C+zBCu/kZSY/R8stwJoiitki3gwIDAQAB",
    "mSafeCode": "V04XQZNYRWN6T0JODZFIAG5CTZB3PT0=",
    "dataIv": "OC1A06E197EF10CF3F6058CA7A803B5E",
    "pkg": "com.djlxxl.xcydzkj",
    "host": "https://az1-1456692500.cos.ap-guangzhou.myqcloud.com/az1.txt",
    "vName": "7.0.0.2",
    "from": "蓝光4k,蓝光",
}

# 每页条数（与接口 pagesize 保持一致）
PAGE_SIZE = 21

# 分类接口 converUrl 字段 -> (OmniBox 筛选 key, 筛选标题)
# OmniBox 前端要求英文 key + { name, value } 子项，不能再返回 TVBox 的中文 key / { n, v }
FILTER_FIELDS = (
    ("class", "class", "剧情"),
    ("area", "area", "地区"),
    ("year", "year", "年代"),
    ("lang", "lang", "语言"),
    ("star", "star", "演员"),
    ("director", "director", "导演"),
    ("extend_sort", "sort", "排序"),
)

# 源站这几个分类的 converUrl 只是占位数据，按对应条件筛会返回 0 条，整组不展示
FILTER_SKIP = {
    "直播": ("剧情", "地区", "年代", "语言", "演员", "导演"),
    "漫剧": ("年代",),
}

# 个别取值实测没有内容（2026-11-19 全量抽查 442 项，空 26 项），这里隐藏掉
FILTER_HIDE = {
    "电影": {"剧情": ("经典", "微电影")},
    "剧集": {"剧情": ("乡村", "情景")},
    "动漫": {"地区": ("其他",)},
    "综艺": {"语言": ("闽南语",), "演员": ("周立波",)},
    "纪录片": {"语言": ("闽南语",)},
    "短剧": {"年代": ("2019", "2018", "2017", "2016", "2015", "2014", "2013",
                      "2012", "2011", "2010", "2008", "2007", "2006", "2004",
                      "2003", "2002", "2001", "2000")},
}

_CACHE_DOMAIN = "hetun:domain"
_CACHE_DYNKEY = "hetun:dynkey"


# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------

async def _log(level, message):
    try:
        await OmniBox.log(level, "[hetun] " + str(message))
    except Exception:
        pass


async def _cache_get(key):
    try:
        fn = getattr(OmniBox, "getCache", None)
        if fn:
            return await fn(key)
    except Exception:
        pass
    return None


async def _cache_set(key, value, ttl):
    try:
        fn = getattr(OmniBox, "setCache", None)
        if fn:
            await fn(key, value, ttl)
    except Exception:
        pass


async def _call(func, *args):
    """同步的底层请求放到线程里跑，避免阻塞 OmniBox 的 async 事件循环。"""
    to_thread = getattr(asyncio, "to_thread", None)
    if to_thread:
        return await to_thread(func, *args)
    return func(*args)


def _env(name, default=""):
    return str(os.environ.get(name, default) or "").strip()


def _to_int(value, default=1):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _load_config(config_path, config_key=None):
    """兼容旧版 extend 的远程配置加载（URL$配置键）。"""
    if requests is None:
        return None
    try:
        content = requests.get(config_path, headers={}, timeout=12).text
        try:
            config = json.loads(content)
        except Exception:
            content = re.sub(r'(export\s+default\s+|module\.exports\s*=)|//.*?$|/\*.*?\*/',
                             '', content, flags=re.MULTILINE | re.DOTALL)
            config = json.loads(re.search(r'(\{[\s\S]*\})', content).group(1))
        return config.get(config_key) if config_key else config
    except Exception:
        return None


def _build_config():
    cfg = dict(CONFIG)

    raw_json = _env("HT_CONFIG_JSON")
    if raw_json.startswith("{"):
        try:
            ext = json.loads(raw_json)
            if isinstance(ext, dict):
                cfg.update(ext)
        except Exception:
            pass

    # 官方推荐：普通采集站地址优先复用 SITE_API
    site_api = _env("SITE_API")
    if site_api:
        cfg["host"] = site_api

    for env_name, key in (("HT_PUBLIC_KEY", "publicKey"), ("HT_SAFE_CODE", "mSafeCode"),
                          ("HT_DATA_IV", "dataIv"), ("HT_PKG", "pkg"),
                          ("HT_VNAME", "vName"), ("HT_FROM", "from")):
        value = _env(env_name)
        if value:
            cfg[key] = value

    extend = _env("HT_EXTEND")
    if extend:
        if "$" in extend:
            path, key = extend.split("$", 1)
            ext = _load_config(path.strip(), key.strip())
            if isinstance(ext, dict):
                cfg.update(ext)
            elif ext:
                cfg["host"] = str(ext).strip()
        elif extend.startswith("{"):
            try:
                ext = json.loads(extend)
                if isinstance(ext, dict):
                    cfg.update(ext)
            except Exception:
                pass
        else:
            cfg["host"] = extend
    return cfg


def _map_vod(item):
    """站点字段 -> OmniBox VodItem 标准字段。"""
    item = item or {}
    return {
        "vod_id": str(item.get("vod_id", "") or ""),
        "vod_name": str(item.get("vod_name", "") or ""),
        "vod_pic": str(item.get("vod_pic", "") or ""),
        "type_id": str(item.get("type_id", "") or ""),
        "type_name": str(item.get("type_name", "") or ""),
        "vod_remarks": str(item.get("vod_remarks", "") or ""),
        "vod_year": str(item.get("vod_year", "") or ""),
        "vod_area": str(item.get("vod_area", "") or ""),
        "vod_douban_score": str(item.get("vod_douban_score", "") or ""),
    }


def _absolute(url, host, base_url=""):
    if not url:
        return ""
    if url.startswith("//"):
        return "https:" + url
    if url.startswith("/"):
        return (host or base_url or "").rstrip("/") + url
    return url


def _empty_list_result(page=1):
    return {"page": page, "pagecount": 0, "total": 0, "list": []}


def _empty_play_result(flag=""):
    return {"urls": [], "url": "", "flag": flag, "header": {}, "parse": 1, "danmaku": []}


def _collect_filters(params):
    """把 OmniBox 的 filters / extend / 平铺键统一拍平成 { key: value }。"""
    merged = {}

    def put(key, value):
        key = str(key or "").strip()
        if not key or key in ("filters", "extend", "categoryId", "page", "keyword",
                              "wd", "quick", "videoId", "playId", "flag", "context"):
            return
        if isinstance(value, dict):
            value = value.get("value", value.get("v", ""))
        if isinstance(value, (list, tuple)):
            value = value[0] if value else ""
        if value is None:
            return
        value = str(value).strip()
        if value and value != "全部":
            merged[key] = value

    for candidate in (params.get("filters"), params.get("extend"), params):
        if isinstance(candidate, dict):
            for k, v in candidate.items():
                put(k, v)
        elif isinstance(candidate, (list, tuple)):
            for entry in candidate:
                if isinstance(entry, dict):
                    put(entry.get("key"), entry.get("value", entry.get("v", "")))
    return merged


# ---------------------------------------------------------------------------
# 源站客户端：保留原脚本的 protobuf / RSA / AES 实现
# ---------------------------------------------------------------------------

class HtClient(object):
    def __init__(self):
        self.cfg = _build_config()
        self.host = str(self.cfg.get("host", "")).rstrip("/")
        self.public_key = str(self.cfg.get("publicKey", ""))
        self.data_key = str(self.cfg.get("mSafeCode", ""))
        self.data_iv = str(self.cfg.get("dataIv", ""))
        self.common_key = "ed5fdsgucxumegqa"
        self.version = str(self.cfg.get("vName", "3.0.2.1"))
        self.session = requests.Session() if requests else None
        self.dynamic_key = ""

        from_config = self.cfg.get("from", "")
        self.line_order, self.line_block = [], []
        if from_config and "@" in from_config:
            parts = str(from_config).split("@")
            if parts[0].strip():
                self.line_order = [k.strip() for k in re.split(r',|@@', parts[0]) if k.strip()]
            if len(parts) > 1 and parts[1].strip():
                self.line_block = [k.strip() for k in re.split(r',|@@', parts[1]) if k.strip()]
        elif from_config:
            self.line_order = [k.strip() for k in re.split(r',|@@', str(from_config)) if k.strip()]

        env_order = _env("HT_LINE_ORDER")
        env_block = _env("HT_LINE_BLOCK")
        if env_order:
            self.line_order = [k.strip() for k in env_order.split(",") if k.strip()]
        if env_block:
            self.line_block = [k.strip() for k in env_block.split(",") if k.strip()]

    async def prepare(self):
        """解析配置域名 + 动态公钥；失败只记日志，由具体接口再兜底。"""
        if requests is None or AES is None or RSA is None:
            raise RuntimeError("缺少依赖 requests / pycryptodome，请确认 @dependencies 已安装")
        if not self.host:
            raise RuntimeError("接口地址未配置，请设置 SITE_API 或 HT_CONFIG_JSON")

        if self.host.endswith((".txt", ".json")):
            domain = await _cache_get(_CACHE_DOMAIN)
            if not domain:
                try:
                    domain = str(self.session.get(self.host, timeout=12).json().get("domain", "")).strip().rstrip("/")
                except Exception as e:
                    await _log("warn", "[init] 配置域名解析失败: %s" % e)
                    domain = ""
            if domain:
                self.host = domain
                await _cache_set(_CACHE_DOMAIN, domain, 3600)

        cached_key = await _cache_get(_CACHE_DYNKEY)
        if cached_key:
            self.dynamic_key = str(cached_key)
        else:
            try:
                self._load_dynamic_key()
                if self.dynamic_key:
                    await _cache_set(_CACHE_DYNKEY, self.dynamic_key, 600)
            except Exception as e:
                await _log("warn", "[init] 动态公钥获取失败，回退内置公钥: %s" % e)

    # ---- protobuf 编解码 ----
    @staticmethod
    def _varint(value):
        value = int(value)
        out = bytearray()
        while value > 0x7f:
            out.append((value & 0x7f) | 0x80)
            value >>= 7
        out.append(value)
        return bytes(out)

    @classmethod
    def _pb_int(cls, field, value):
        return cls._varint(field << 3) + cls._varint(value)

    @classmethod
    def _pb_bytes(cls, field, value):
        if isinstance(value, str):
            value = value.encode("utf-8")
        return cls._varint((field << 3) | 2) + cls._varint(len(value)) + value

    @staticmethod
    def _read_varint(data, pos):
        value = 0
        shift = 0
        while pos < len(data):
            b = data[pos]
            pos += 1
            value |= (b & 0x7f) << shift
            if not b & 0x80:
                return value, pos
            shift += 7
        raise ValueError("bad protobuf varint")

    @classmethod
    def _pb_parse(cls, data):
        fields = {}
        pos = 0
        while pos < len(data):
            key, pos = cls._read_varint(data, pos)
            field, wire = key >> 3, key & 7
            if wire == 0:
                value, pos = cls._read_varint(data, pos)
            elif wire == 1:
                value = data[pos:pos + 8]
                pos += 8
            elif wire == 2:
                size, pos = cls._read_varint(data, pos)
                value = data[pos:pos + size]
                pos += size
            elif wire == 5:
                value = data[pos:pos + 4]
                pos += 4
            else:
                raise ValueError("unsupported protobuf wire type: %s" % wire)
            fields.setdefault(field, []).append(value)
        return fields

    @staticmethod
    def _first(fields, number, default=b""):
        values = fields.get(number)
        return values[0] if values else default

    @staticmethod
    def _text(value):
        if isinstance(value, bytes):
            return value.decode("utf-8", "ignore")
        return str(value or "")

    @staticmethod
    def _unescape(text):
        """还原接口里的 HTML 实体（&#039; &amp; 等），否则名字/封面地址会带乱码。"""
        if not text or "&" not in str(text):
            return text
        text = str(text)
        text = re.sub(r"&#x([0-9a-fA-F]+);", lambda m: chr(int(m.group(1), 16)), text)
        text = re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1))), text)
        for src, dst in (("&quot;", '"'), ("&apos;", "'"), ("&nbsp;", " "),
                         ("&lt;", "<"), ("&gt;", ">"), ("&amp;", "&")):
            text = text.replace(src, dst)
        return text

    @classmethod
    def _clean(cls, value, default=""):
        return cls._unescape(cls._text(value)) or default

    @classmethod
    def _clean_area(cls, value):
        """个别条目的地区字段夹带 JSON 碎片，截掉引号/花括号后面的脏尾巴。"""
        text = cls._clean(value)
        text = re.split(r'["{}&]', text, 1)[0]
        return re.sub(r"\s+", " ", text).strip()

    # ---- 加密 / 签名 ----
    @staticmethod
    def _random(length):
        chars = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        return "".join(random.choice(chars) for _ in range(max(0, length - 1))) + "="

    @staticmethod
    def _check_crypto():
        if AES is None or RSA is None:
            raise RuntimeError("缺少 pycryptodome")

    @classmethod
    def _aes_encrypt_ecb(cls, text, key):
        cls._check_crypto()
        cipher = AES.new(key.encode("utf-8"), AES.MODE_ECB)
        return base64.b64encode(cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))).decode("utf-8")

    @classmethod
    def _aes_decrypt_ecb(cls, text, key):
        cls._check_crypto()
        raw = base64.b64decode(text)
        cipher = AES.new(key.encode("utf-8"), AES.MODE_ECB)
        return unpad(cipher.decrypt(raw), AES.block_size).decode("utf-8", "ignore")

    @classmethod
    def _aes_encrypt_cbc_hex(cls, text, key):
        cls._check_crypto()
        key_b = key.encode("utf-8")
        cipher = AES.new(key_b, AES.MODE_CBC, iv=key_b)
        return cipher.encrypt(pad(text.encode("utf-8"), AES.block_size)).hex()

    @classmethod
    def _rsa_encrypt(cls, text, public_key_b64):
        cls._check_crypto()
        der = base64.b64decode(public_key_b64)
        key = RSA.import_key(der)
        return base64.b64encode(PKCS1_v1_5.new(key).encrypt(text.encode("utf-8"))).decode("utf-8")

    def _device(self):
        uid = uuid.uuid4().hex.upper()
        return {
            "country": "CN", "vName": self.version, "cpuId": "MT6893Z%2FCZA", "young": 0,
            "facturer": "Xiaomi", "pkg": self.cfg.get("pkg", ""), "uuid": uid,
            "resolution": "1080x2272", "mac": "02%3A00%3A00%3A00%3A00%3A00", "abid": "397",
            "model": "M2012K11AC", "plat": "android", "udid": uid, "dpi": "440", "net": "1",
            "lang": "zh", "brand": "Xiaomi", "density": "2.75",
            "appName": self.cfg.get("appName", "橘汁"),
            "cpu": "arm64-v8a", "chid": "10000", "carrier": "%E8%81%94%E9%80%9A",
            "_vOsCode": 30, "vOs": "11", "v": 1, "tenantId": "",
            "vApp": self.version.replace(".", ""), "device": 0, "androidID": uid.lower()[:16]
        }

    def _public_headers(self, protobuf=True):
        key = self.dynamic_key or self.public_key
        device = self._device()
        timestamp = int(time.time() * 1000)
        random_str = self._random(16)
        vapp = device.get("vApp") or "3019"
        device["sig"] = self._rsa_encrypt(str(timestamp) + random_str + vapp, key)
        device["random_str"] = random_str
        device["timestamp"] = timestamp
        sig23 = self._aes_encrypt_ecb(str(timestamp) + random_str, self.data_iv)
        device["sig2"] = sig23[:8]
        device["sig3"] = sig23[8:]
        params = self._aes_encrypt_cbc_hex(json.dumps(device, ensure_ascii=False, separators=(",", ":")),
                                           self.common_key)
        ctype = "application/x-protobuf" if protobuf else "application/json; charset=utf-8"
        accept = "application/x-protobuf" if protobuf else "application/json"
        return {
            "User-Agent": "okhttp/3.12.1", "Accept": accept, "Content-Type": ctype,
            "publicParams": json.dumps({"paramsData": params}, ensure_ascii=False, separators=(",", ":"))
        }

    def _secure_body(self, params):
        timestamp = int(time.time() * 1000)
        random8 = self._random(8)
        fake20 = self._random(20)
        query = "&".join("%s=%s" % (k, v) for k, v in params.items() if v is not None and str(v) != "")
        encrypted = random8 + self._aes_encrypt_ecb(query + str(timestamp), self.data_key)
        return b"".join([
            self._pb_bytes(1, encrypted[:20]), self._pb_bytes(2, encrypted[20:]),
            self._pb_bytes(3, fake20), self._pb_int(4, timestamp), self._pb_bytes(5, random8)
        ])

    def _post(self, path, body):
        if not self.session or not self.host:
            raise RuntimeError("接口域名获取失败")
        r = self.session.post(self.host + path, data=body, headers=self._public_headers(True), timeout=18)
        r.raise_for_status()
        return r.content

    def _get_json(self, path):
        if not self.session or not self.host:
            raise RuntimeError("接口域名获取失败")
        r = self.session.get(self.host + path, headers=self._public_headers(False), timeout=18)
        r.raise_for_status()
        return r.json()

    def _api_data(self, raw):
        return self._first(self._pb_parse(raw), 3, b"")

    def _load_dynamic_key(self):
        timestamp = int(time.time() * 1000)
        random_str = self._random(16)
        sign = self._rsa_encrypt(str(timestamp) + random_str, self.public_key)
        body = b"".join([
            self._pb_int(1, timestamp), self._pb_bytes(2, sign), self._pb_bytes(3, self._random(16)),
            self._pb_bytes(4, random_str), self._pb_bytes(5, self._random(16))
        ])
        data = self._api_data(self._post("/api/v5/find/app/zone", body))
        f = self._pb_parse(data)
        self.dynamic_key = "".join(self._text(self._first(f, n)) for n in (2, 3, 4, 5))

    # ---- 解析 ----
    def _parse_cover(self, raw):
        f = self._pb_parse(raw)
        return {"path": self._clean(self._first(f, 1)), "thumb": self._clean(self._first(f, 2))}

    def _parse_drama(self, raw):
        f = self._pb_parse(raw)
        cover_raw = self._first(f, 2, b"")
        cover = self._parse_cover(cover_raw) if cover_raw else {}
        return {
            "vod_id": str(self._first(f, 3, 0)), "vod_name": self._clean(self._first(f, 5)),
            "vod_pic": cover.get("thumb") or cover.get("path", ""),
            "vod_remarks": self._clean(self._first(f, 13)),
            "vod_year": str(self._first(f, 14, "")), "vod_area": self._clean_area(self._first(f, 1))
        }

    @classmethod
    def _pb_total(cls, fields):
        """列表接口第 16 字段是当前筛选条件下的总条数。"""
        value = cls._first(fields, 16, 0)
        if isinstance(value, bytes):
            try:
                value = cls._read_varint(value, 0)[0]
            except Exception:
                return 0
        try:
            return max(0, int(value))
        except Exception:
            return 0

    @staticmethod
    def _split_filter_values(raw):
        if isinstance(raw, (list, tuple)):
            values = [str(v).strip() for v in raw]
        else:
            values = [v.strip() for v in str(raw or "").split(",")]
        result = []
        for value in values:
            if value and value not in result:
                result.append(value)
        return result

    def _build_filters(self, items):
        """converUrl -> OmniBox 格式：{ 分类ID: [{ key, name, init, value: [{name, value}] }] }"""
        filters = {}
        for item in items or []:
            tid = str(item.get("id") or "").strip()
            if not tid:
                continue
            name = str(item.get("name") or "").strip()
            skip = FILTER_SKIP.get(name, ())
            hide = FILTER_HIDE.get(name, {})
            try:
                data = json.loads(item.get("converUrl") or "{}")
            except Exception:
                data = {}
            if not isinstance(data, dict):
                data = {}
            groups = []
            for field, key, label in FILTER_FIELDS:
                if label in skip:
                    continue
                hidden = hide.get(label, ())
                values = [v for v in self._split_filter_values(data.get(field)) if v not in hidden]
                if not values:
                    continue
                options = [] if label == "排序" else [{"name": "全部", "value": ""}]
                options.extend({"name": value, "value": value} for value in values)
                init = "" if label != "排序" else ("最新" if "最新" in values else values[0])
                groups.append({"key": key, "name": label, "init": init, "value": options})
            if groups:
                filters[tid] = groups
        return filters

    @staticmethod
    def _extend_get(extend, keys, default=""):
        """extend 里取值：兼容中文键和英文键，空值视为未选。"""
        for key in keys:
            value = extend.get(key)
            if value is None:
                continue
            value = str(value).strip()
            if value and value != "全部":
                return value
        return default

    def _parse_video(self, raw):
        f = self._pb_parse(raw)
        return {
            "title": self._text(self._first(f, 2)), "path": self._text(self._first(f, 4)),
            "source": self._text(self._first(f, 9)), "source_cn": self._text(self._first(f, 10))
        }

    @staticmethod
    def _is_match_line(line_name, keyword):
        name = line_name.strip().lower()
        key = keyword.strip()
        try:
            if key.startswith("/") and key.endswith("/"):
                return bool(re.search(key[1:-1], name, re.IGNORECASE))
        except Exception:
            pass
        return key.lower() in name

    def _sort_and_filter_lines(self, lines):
        if not lines:
            return lines
        if self.line_block:
            lines = [l for l in lines
                     if not any(self._is_match_line(l["name"], kw) for kw in self.line_block)]
        if self.line_order:
            sorted_lines, remaining = [], lines[:]
            for keyword in self.line_order:
                matched, unmatched = [], []
                for line in remaining:
                    (matched if self._is_match_line(line["name"], keyword) else unmatched).append(line)
                sorted_lines.extend(matched)
                remaining = unmatched
            lines = sorted_lines + remaining
        return lines

    @staticmethod
    def isVideoFormat(url):
        return bool(re.search(r"(?i)\.(?:mp4|m3u8|flv|mkv|avi|ts|mov|mpd|m4a|wmv)(?:\?.*)?$", str(url)))

    # ---- 站点接口（同步，供 async handler 通过 _call 调用）----
    def home_content(self):
        classes, filters = [], {}
        obj = self._get_json("/api/v3/drama/getCategory?orderBy=type_id")
        data = obj.get("data") or []
        for item in data:
            if str(item.get("name", "")) == "公告":
                continue
            tid, name = str(item.get("id", "")), str(item.get("name", ""))
            if not tid:
                continue
            classes.append({"type_id": tid, "type_name": name})
        filters = self._build_filters(data)
        return classes, filters

    def home_video_content(self):
        obj = self._get_json("/api/ex/v3/security/tag/list")
        data = obj.get("data", "")
        if data and isinstance(data, str):
            stripped = data.strip()
            if stripped and stripped[0] not in ("[", "{"):
                data = self._aes_decrypt_ecb(data, self.data_key)
                data = self._aes_decrypt_ecb(data, self.data_iv)
        arr = json.loads(data) if isinstance(data, str) else data
        videos = []
        for block in arr or []:
            for section in block.get("sections") or []:
                for vod in section.get("vodList") or []:
                    pic = (vod.get("coverImage") or {}).get("path", "")
                    videos.append({
                        "vod_id": str(vod.get("id", "")), "vod_name": vod.get("name", ""),
                        "vod_pic": pic, "vod_remarks": vod.get("remark", "")
                    })
        return videos

    def category_content(self, tid, page, extend):
        ext = extend if isinstance(extend, dict) else {}
        params = {
            "pagesize": str(PAGE_SIZE),
            "typeId1": str(tid),
            "page": str(page),
            "vodOrderBy": self._extend_get(ext, ("排序", "sort", "order", "extend_sort"), "最新"),
            "vodArea": self._extend_get(ext, ("地区", "area")),
            "vodLang": self._extend_get(ext, ("语言", "lang")),
            "vodClass": self._extend_get(ext, ("剧情", "类型", "class")),
            "vodYear": self._extend_get(ext, ("年代", "年份", "year")),
            "vodActor": self._extend_get(ext, ("演员", "star", "actor")),
            "vodDirector": self._extend_get(ext, ("导演", "director")),
        }
        data = self._pb_parse(self._api_data(
            self._post("/api/proto/v5/drama/category", self._secure_body(params))))
        dramas, seen = [], set()
        for item in data.get(1, []) or []:
            if not isinstance(item, bytes):
                continue
            vod = self._parse_drama(item)
            if not vod.get("vod_id") or vod["vod_id"] in seen:
                continue
            seen.add(vod["vod_id"])
            dramas.append(vod)
        total = self._pb_total(data)
        pagecount = (total + PAGE_SIZE - 1) // PAGE_SIZE if total else 9999
        return {"list": dramas, "page": page, "pagecount": pagecount,
                "limit": PAGE_SIZE, "total": total or len(dramas)}

    def detail_sources(self, video_id, from_val="web"):
        """返回 { vod, play_sources, tvbox }：OmniBox 用 play_sources，TV 端额外兼容 vod_play_from/url。"""
        raw = self._post("/api/proto/v5/drama/getDetail", self._secure_body({"id": str(video_id)}))
        f = self._pb_parse(self._api_data(raw))
        cover_raw = self._first(f, 2, b"")
        cover = self._parse_cover(cover_raw) if cover_raw else {}
        sources = {}
        for item in f.get(29, []):
            video = self._parse_video(item)
            quality = video.get("source_cn", "") or video.get("source", "") or "未知"
            source = video.get("source", "") or ""
            line_name = "%s (%s)" % (quality, source) if source and quality != source else quality
            path = video["path"]
            if not self.isVideoFormat(path):
                token = base64.b64encode(json.dumps(
                    {"vodPlayFrom": video["source"], "playUrl": path},
                    ensure_ascii=False, separators=(",", ":")).encode()).decode()
                token_raw = token
            else:
                token_raw = path
                # web 端 detail -> play -> 前端链路，带 & 或中文的 URL 先编码再透传
                if from_val == "web" and ("&" in path or re.search(r"[\u4e00-\u9fff]", path)):
                    token = "enc:" + quote(path, safe="")
                else:
                    token = path
            sources.setdefault(line_name, []).append((video["title"] or "播放", token, token_raw))

        lines = [{"name": name, "urls": urls} for name, urls in sources.items()]
        lines = self._sort_and_filter_lines(lines)

        play_sources = []
        for line in lines:
            episodes = [{"name": title, "playId": token} for title, token, _ in line["urls"] if token]
            if episodes:
                play_sources.append({"name": line["name"], "episodes": episodes})

        tvbox = {
            "vod_play_from": "$$$".join(line["name"] for line in lines),
            "vod_play_url": "$$$".join(
                "#".join("%s$%s" % (title, raw_token) for title, _, raw_token in line["urls"])
                for line in lines),
        }

        vod = {
            "vod_id": str(video_id), "vod_name": self._clean(self._first(f, 9)),
            "vod_pic": cover.get("path") or cover.get("thumb", ""),
            "vod_actor": self._clean(self._first(f, 25)), "vod_director": self._clean(self._first(f, 12)),
            "vod_area": self._clean_area(self._first(f, 1)), "vod_year": str(self._first(f, 18, "")),
            "vod_remarks": self._clean(self._first(f, 26)), "vod_content": self._clean(self._first(f, 6)),
        }
        return {"vod": vod, "play_sources": play_sources, "tvbox": tvbox}

    def search_content(self, key, page):
        data = self._pb_parse(self._api_data(
            self._post("/api/proto/v5/drama/search",
                       self._secure_body({"searchKeys": key, "page": str(page),
                                          "pagesize": str(PAGE_SIZE)}))))
        results, seen = [], set()
        for item in data.get(1, []) or []:
            if not isinstance(item, bytes):
                continue
            vod = self._parse_drama(item)
            if not vod.get("vod_id") or vod["vod_id"] in seen:
                continue
            seen.add(vod["vod_id"])
            results.append(vod)
        total = self._pb_total(data)
        pagecount = (total + PAGE_SIZE - 1) // PAGE_SIZE if total else (1 if results else 0)
        return {"list": results, "page": page, "pagecount": pagecount,
                "limit": PAGE_SIZE, "total": total or len(results)}

    def player_content(self, play_id):
        if self.isVideoFormat(play_id):
            return {"parse": 0, "url": play_id, "header": {}}
        params = json.loads(base64.b64decode(play_id).decode("utf-8"))
        raw = self._post("/api/proto/v5/videoUsableUrl", self._secure_body(params))
        f = self._pb_parse(self._api_data(raw))
        headers = {}
        for entry in f.get(6, []):
            ef = self._pb_parse(entry)
            k, v = self._text(self._first(ef, 1)), self._text(self._first(ef, 2))
            if k:
                headers[k] = v
        return {"parse": 0, "url": self._text(self._first(f, 1)), "header": headers}


_CLIENT = None


async def _get_client():
    """懒加载单例。不使用 asyncio.Lock：运行器可能每次请求新建事件循环，
    锁对象跨 loop 复用有绑定风险；并发初始化最多多一次配置请求，可接受。"""
    global _CLIENT
    if _CLIENT is None:
        client = HtClient()
        await client.prepare()
        _CLIENT = client
    return _CLIENT


# ---------------------------------------------------------------------------
# OmniBox 五个标准 handler：(params, context)
# ---------------------------------------------------------------------------

async def home(params, context):
    params = params or {}
    ctx = context or {}
    from_val = ctx.get("from", "web") or "web"
    await _log("info", "[home] params=%s from=%s sourceId=%s"
               % (params, from_val, ctx.get("sourceId", "")))
    try:
        client = await _get_client()
        classes, filters = await _call(client.home_content)
        try:
            recommends = await _call(client.home_video_content)
        except Exception as e:
            await _log("warn", "[home] 推荐列表获取失败，首页仅返回分类: %s" % e)
            recommends = []
        result = {
            "class": classes,
            "filters": filters,
            "list": [_map_vod(v) for v in recommends],
        }
        await _log("info", "[home] 分类=%s 筛选分类=%s 推荐=%s"
                   % (len(classes), len(filters), len(result["list"])))
        return result
    except Exception as e:
        await _log("error", "[home] 失败: %s" % e)
        return {"class": [], "filters": {}, "list": []}


async def category(params, context):
    params = params or {}
    ctx = context or {}
    from_val = ctx.get("from", "web") or "web"
    category_id = str(params.get("categoryId") or params.get("tid") or params.get("type_id") or "")
    page = max(1, _to_int(params.get("page") or 1, 1))
    filters = _collect_filters(params)
    await _log("info", "[category] categoryId=%s page=%s filters=%s from=%s"
               % (category_id, page, filters, from_val))
    try:
        client = await _get_client()
        result = await _call(client.category_content, category_id, page, filters)
        out = {
            "page": _to_int(result.get("page"), page),
            "pagecount": _to_int(result.get("pagecount"), 0),
            "total": _to_int(result.get("total"), 0),
            "list": [_map_vod(v) for v in result.get("list") or []],
        }
        await _log("info", "[category] 返回 %s 条 / 共 %s 条 / %s 页"
                   % (len(out["list"]), out["total"], out["pagecount"]))
        return out
    except Exception as e:
        await _log("error", "[category] 失败: %s" % e)
        return _empty_list_result(page)


async def detail(params, context):
    params = params or {}
    ctx = context or {}
    from_val = ctx.get("from", "web") or "web"
    video_id = str(params.get("videoId") or params.get("vod_id") or params.get("id") or "")
    await _log("info", "[detail] videoId=%s from=%s" % (video_id, from_val))
    if not video_id:
        return {"list": []}
    try:
        client = await _get_client()
        raw = await _call(client.detail_sources, video_id, from_val)
        vod = _map_vod(raw.get("vod"))
        for key in ("vod_content", "vod_actor", "vod_director", "vod_area",
                    "vod_year", "vod_remarks", "vod_pic", "type_name"):
            if raw.get("vod", {}).get(key):
                vod[key] = str(raw["vod"][key])
        vod["vod_play_sources"] = raw.get("play_sources") or []
        # TV / UZ / catvod / emby 端额外附带传统字段，web 端只用标准结构
        if from_val in ("tvbox", "catvod", "uz", "emby"):
            vod.update(raw.get("tvbox") or {})
        await _log("info", "[detail] 线路=%s 集数=%s"
                   % (len(vod["vod_play_sources"]),
                      sum(len(s.get("episodes") or []) for s in vod["vod_play_sources"])))
        return {"list": [vod]}
    except Exception as e:
        await _log("error", "[detail] 失败: %s" % e)
        return {"list": []}


async def search(params, context):
    params = params or {}
    ctx = context or {}
    from_val = ctx.get("from", "web") or "web"
    keyword = str(params.get("keyword") or params.get("wd") or "").strip()
    page = max(1, _to_int(params.get("page") or 1, 1))
    await _log("info", "[search] keyword=%s page=%s quick=%s from=%s"
               % (keyword, page, params.get("quick", False), from_val))
    if not keyword:
        return _empty_list_result(1)
    try:
        client = await _get_client()
        result = await _call(client.search_content, keyword, page)
        out = {
            "page": _to_int(result.get("page"), page),
            "pagecount": _to_int(result.get("pagecount"), 0),
            "total": _to_int(result.get("total"), 0),
            "list": [_map_vod(v) for v in result.get("list") or []],
        }
        await _log("info", "[search] 返回 %s 条 / 共 %s 条" % (len(out["list"]), out["total"]))
        return out
    except Exception as e:
        await _log("error", "[search] 失败: %s" % e)
        return _empty_list_result(page)


async def play(params, context):
    params = params or {}
    ctx = context or {}
    from_val = ctx.get("from", "web") or "web"
    play_id = str(params.get("playId") or params.get("id") or params.get("url") or "")
    flag = str(params.get("flag") or "")
    await _log("info", "[play] playId=%s flag=%s from=%s" % (play_id, flag, from_val))
    if not play_id:
        await _log("error", "[play] playId 为空")
        return _empty_play_result(flag)
    if play_id.startswith("enc:"):
        play_id = unquote(play_id[4:])
        await _log("info", "[play] 已解码 web 端透传 URL: %s" % play_id)
    try:
        client = await _get_client()
        result = await _call(client.player_content, play_id)
        url = _absolute(result.get("url", ""), client.host, ctx.get("baseURL", ""))
        if not url:
            raise RuntimeError("接口未返回播放地址")
        header = result.get("header") or {}
        if from_val == "web" and header:
            await _log("warn", "[play] web 端 header 不可靠，已尽量在 play() 内解出最终直链: %s" % list(header))
        out = {
            "urls": [{"name": "播放", "url": url}],
            "url": url,
            "flag": flag,
            "header": header,
            "parse": _to_int(result.get("parse"), 0),
            "danmaku": [],
        }
        await _log("info", "[play] 返回 url=%s header=%s parse=%s"
                   % (url, list(header), out["parse"]))
        return out
    except Exception as e:
        await _log("error", "[play] 失败: %s playId=%s" % (e, play_id))
        return _empty_play_result(flag)


if __name__ == "__main__":
    run({
        "home": home,
        "category": category,
        "detail": detail,
        "search": search,
        "play": play,
    })
