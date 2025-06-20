import asyncio
import time
import httpx
import json
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB49"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "IND":
        return "uid=3959790412&password=30521D697B600260C86371342124D9DC0A79B772D038F474C67C814E5D71AEF4"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=uid&password=password"
    else:
        return "uid=uid&password=password"

# === Token Generation ===
async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)
    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1",
               'X-GA': "v1 1", 'ReleaseVersion': RELEASEVERSION}
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
        cached_tokens[region] = {
            'token': f"Bearer {msg.get('token','0')}",
            'region': msg.get('lockRegion','0'),
            'server_url': msg.get('serverUrl','0'),
            'expires_at': time.time() + 25200
        }

async def initialize_tokens():
    tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str,str,str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, region, endpoint):
    region = region.upper()
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region)
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue",
               'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
               'ReleaseVersion': RELEASEVERSION}
    async with httpx.AsyncClient() as client:
        resp = await client.post(server+endpoint, data=data_enc, headers=headers)
        return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))

# === Caching Decorator ===
def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(request.args.items()))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator

# === Flask Routes ===
@app.route('/playerpersonalshow')
@cached_endpoint()
def get_account_info():
    region = request.args.get('region')
    uid = request.args.get('uid')

    if not uid:
        return jsonify({"error": "Please provide UID."}), 400
    if not region:
        return jsonify({"error": "Please provide REGION."}), 400

    try:
        raw_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
        
        # Check if elite pass is owned (your custom logic)
        has_elite_pass = raw_data["basicInfo"].get("hasElitePass", False)
        if not has_elite_pass:
            has_elite_pass = any(str(item).startswith('9') for item in raw_data.get("profileInfo", {}).get("equipedItems", []))

        # Build the response
        response = {
            "AccountInfo": {
                "AccountAvatarId": raw_data.get("basicInfo", {}).get("headPic", 0),
                "AccountBPBadges": raw_data.get("basicInfo", {}).get("badgeCnt", 0),
                "AccountBPID": raw_data.get("basicInfo", {}).get("badgeId", 0),
                "AccountBannerId": raw_data.get("basicInfo", {}).get("bannerId", 0),
                "AccountCreateTime": raw_data.get("basicInfo", {}).get("createAt", 0),
                "AccountEXP": raw_data.get("basicInfo", {}).get("exp", 0),
                "AccountLastLogin": raw_data.get("basicInfo", {}).get("lastLoginAt", 0),
                "AccountLevel": raw_data.get("basicInfo", {}).get("level", 0),
                "AccountLikes": raw_data.get("basicInfo", {}).get("liked", 0),
                "AccountName": raw_data.get("basicInfo", {}).get("nickname", ""),
                "AccountRegion": raw_data.get("basicInfo", {}).get("region", ""),
                "AccountSeasonId": raw_data.get("basicInfo", {}).get("seasonId", 0),
                "AccountType": raw_data.get("basicInfo", {}).get("accountType", 0),
                "AvatarImage": f"https://www.dl.cdn.freefireofficial.com/icons/{raw_data.get('basicInfo', {}).get('headPic', 0)}.png",
                "BannerImage": f"https://www.dl.cdn.freefireofficial.com/icons/{raw_data.get('basicInfo', {}).get('bannerId', 0)}.png",
                "BrMaxRank": raw_data.get("basicInfo", {}).get("maxRank", 0),
                "BrRankPoint": raw_data.get("basicInfo", {}).get("rankingPoints", 0),
                "CsMaxRank": raw_data.get("basicInfo", {}).get("csMaxRank", 0),
                "CsRankPoint": raw_data.get("basicInfo", {}).get("csRankingPoints", 0),
                "EquippedWeapon": raw_data.get("basicInfo", {}).get("weaponSkinShows", []),
                "EquippedWeaponImages": [
                    f"https://www.dl.cdn.freefireofficial.com/icons/{weapon}.png" 
                    for weapon in raw_data.get("basicInfo", {}).get("weaponSkinShows", [])
                ],
                "ReleaseVersion": raw_data.get("basicInfo", {}).get("releaseVersion", ""),
                "Role": raw_data.get("basicInfo", {}).get("role", 0),
                "ShowBrRank": raw_data.get("basicInfo", {}).get("showBrRank", False),
                "ShowCsRank": raw_data.get("basicInfo", {}).get("showCsRank", False),
                "Title": raw_data.get("basicInfo", {}).get("title", 0),
                "hasElitePass": has_elite_pass
            },
            "AccountProfileInfo": {
                "EquippedOutfit": raw_data.get("profileInfo", {}).get("clothes", []),
                "EquippedOutfitImages": [
                    f"https://www.dl.cdn.freefireofficial.com/icons/{item}.png" 
                    for item in raw_data.get("profileInfo", {}).get("clothes", [])
                ],
                "EquippedSkills": raw_data.get("profileInfo", {}).get("equipedSkills", []),
                "EquippedSkillsImages": [
                    "https://i.postimg.cc/BnpRPsjv/Kelly-The-Swift.png",
                    "https://freefiremobile-a.akamaihd.net/common/web_event/official2.ff.garena.all/img/20228/e21eb41a3705ff817156dd5758157274.png",
                    "https://i.postimg.cc/FznQS4Wc/Moco-Rebirth.png",
                    "https://dl.dir.freefiremobile.com/common/web_event/official2.ff.garena.all/202412/b2f635a96ed787a8e540031402ea751b.png"
                ]
            },
            "GuildInfo": {
                "GuildCapacity": raw_data.get("clanBasicInfo", {}).get("capacity", 0),
                "GuildID": raw_data.get("clanBasicInfo", {}).get("clanId", ""),
                "GuildLevel": raw_data.get("clanBasicInfo", {}).get("clanLevel", 0),
                "GuildMember": raw_data.get("clanBasicInfo", {}).get("memberNum", 0),
                "GuildName": raw_data.get("clanBasicInfo", {}).get("clanName", ""),
                "GuildOwner": raw_data.get("clanBasicInfo", {}).get("captainId", "")
            },
            "captainBasicInfo": {
                "EquippedWeapon": raw_data.get("basicInfo", {}).get("weaponSkinShows", []),
                "accountId": uid,
                "accountType": raw_data.get("basicInfo", {}).get("accountType", 0),
                "badgeCnt": raw_data.get("basicInfo", {}).get("badgeCnt", 0),
                "badgeId": str(raw_data.get("basicInfo", {}).get("badgeId", "")),
                "createAt": str(raw_data.get("basicInfo", {}).get("createAt", "")),
                "csMaxRank": raw_data.get("basicInfo", {}).get("csMaxRank", 0),
                "csRank": raw_data.get("basicInfo", {}).get("csRank", 0),
                "csRankingPoints": raw_data.get("basicInfo", {}).get("csRankingPoints", 0),
                "exp": raw_data.get("basicInfo", {}).get("exp", 0),
                "lastLoginAt": str(raw_data.get("basicInfo", {}).get("lastLoginAt", "")),
                "level": raw_data.get("basicInfo", {}).get("level", 0),
                "liked": raw_data.get("basicInfo", {}).get("liked", 0),
                "maxRank": raw_data.get("basicInfo", {}).get("maxRank", 0),
                "nickname": raw_data.get("basicInfo", {}).get("nickname", ""),
                "rank": raw_data.get("basicInfo", {}).get("rank", 0),
                "rankingPoints": raw_data.get("basicInfo", {}).get("rankingPoints", 0),
                "region": region.upper(),
                "releaseVersion": raw_data.get("basicInfo", {}).get("releaseVersion", ""),
                "seasonId": raw_data.get("basicInfo", {}).get("seasonId", 0),
                "showBrRank": raw_data.get("basicInfo", {}).get("showBrRank", False),
                "showCsRank": raw_data.get("basicInfo", {}).get("showCsRank", False),
                "title": raw_data.get("basicInfo", {}).get("title", 0)
            },
            "creditScoreInfo": {
                "creditScore": raw_data.get("creditScoreInfo", {}).get("creditScore", 0),
                "periodicSummaryEndTime": str(raw_data.get("creditScoreInfo", {}).get("periodicSummaryEndTime", "")),
                "rewardState": 1 if raw_data.get("creditScoreInfo", {}).get("rewardState", "") == "REWARD_STATE_UNCLAIMED" else 0
            },
            "petInfo": {
                "exp": raw_data.get("petInfo", {}).get("exp", 0),
                "id": raw_data.get("petInfo", {}).get("id", 0),
                "isSelected": raw_data.get("petInfo", {}).get("isSelected", False),
                "level": raw_data.get("petInfo", {}).get("level", 0),
                "selectedSkillId": raw_data.get("petInfo", {}).get("selectedSkillId", 0),
                "skinId": raw_data.get("petInfo", {}).get("skinId", 0)
            },
            "socialinfo": {
                "AccountLanguage": raw_data.get("socialInfo", {}).get("language", "").replace("Language_", ""),
                "AccountPreferMode": raw_data.get("socialInfo", {}).get("modePrefer", "").replace("ModePrefer_", ""),
                "AccountSignature": raw_data.get("socialInfo", {}).get("signature", "")
            }
        }
        
        return jsonify(response), 200, {'Content-Type': 'application/json; charset=utf-8'}

    except KeyError as e:
        return jsonify({
            "error": f"Required field missing in API response: {str(e)}",
            "details": "The Free Fire API response is missing expected fields"
        }), 500
    except Exception as e:
        return jsonify({
            "error": "Failed to fetch player information",
            "details": str(e)
        }), 500

@app.route('/refresh', methods=['GET','POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message':'Tokens refreshed for all regions.'}),200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}),500

# === Startup ===
async def startup():
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())

if __name__ == '__main__':
    asyncio.run(startup())
    app.run(host='0.0.0.0', port=5000, debug=True)
