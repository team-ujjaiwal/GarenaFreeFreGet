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
@app.route('/player-info')
@cached_endpoint()
def get_account_info():
    region = request.args.get('region')
    uid = request.args.get('uid')

    if not uid:
        return jsonify({"error": "Please provide UID."}), 400
    if not region:
        return jsonify({"error": "Please provide REGION."}), 400

    try:
        # Get raw data from API
        raw_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))

        response = {
            "AccountInfo": {
                "AccountBPBadges": raw_data["basicInfo"]["badgeCnt"],
                "AccountBPID": raw_data["basicInfo"]["badgeId"],
                "AccountCreateTime": raw_data["basicInfo"]["createAt"],
                "AccountEXP": raw_data["basicInfo"]["exp"],
                "AccountLastLogin": raw_data["basicInfo"]["lastLoginAt"],
                "AccountLevel": raw_data["basicInfo"]["level"],
                "AccountLikes": raw_data["basicInfo"]["liked"],
                "AccountName": raw_data["basicInfo"]["nickname"],
                "AccountRegion": region.upper(),
                "AccountSeasonId": raw_data["basicInfo"]["seasonId"],
                "AccountType": raw_data["basicInfo"]["accountType"],
                "BrMaxRank": raw_data["basicInfo"]["maxRank"],
                "BrRankPoint": raw_data["basicInfo"]["rankingPoints"],
                "CsMaxRank": raw_data["basicInfo"]["csMaxRank"],
                "CsRankPoint": raw_data["basicInfo"]["csRankingPoints"],
                "EquippedWeapon": raw_data["basicInfo"]["weaponSkinShows"],
                "EquippedWeaponImages": [
                    f"https://ff-community-api.vercel.app/icons?id={weapon_id}"
                    for weapon_id in raw_data["basicInfo"]["weaponSkinShows"]
                ],
                "ReleaseVersion": raw_data["basicInfo"]["releaseVersion"],
                "ShowBrRank": raw_data["basicInfo"]["showBrRank"],
                "ShowCsRank": raw_data["basicInfo"]["showCsRank"],
                "Title": raw_data["basicInfo"]["title"],
                "hasElitePass": raw_data["basicInfo"]["hasElitePass"]
            },
            "AccountProfileInfo": {
                "EquippedOutfit": raw_data["profileInfo"]["clothes"],
                "EquippedOutfitImages": [
                    f"https://ff-community-api.vercel.app/icons?id={outfit_id}"
                    for outfit_id in raw_data["profileInfo"]["clothes"]
                ],
                "EquippedSkills": raw_data["profileInfo"]["equipedSkills"],
                "EquippedSkillsImages": [
                    "https://i.postimg.cc/BnpRPsjv/Kelly-The-Swift.png",
                    "https://freefiremobile-a.akamaihd.net/common/web_event/official2.ff.garena.all/img/20228/e21eb41a3705ff817156dd5758157274.png",
                    "https://i.postimg.cc/FznQS4Wc/Moco-Rebirth.png",
                    "https://dl.dir.freefiremobile.com/common/web_event/official2.ff.garena.all/202412/b2f635a96ed787a8e540031402ea751b.png"
                ]
            },
            "GuildInfo": {
                "GuildCapacity": raw_data["clanBasicInfo"]["capacity"],
                "GuildID": raw_data["clanBasicInfo"]["clanId"],
                "GuildLevel": raw_data["clanBasicInfo"]["clanLevel"],
                "GuildMember": raw_data["clanBasicInfo"]["memberNum"],
                "GuildName": raw_data["clanBasicInfo"]["clanName"],
                "GuildOwner": raw_data["clanBasicInfo"]["captainId"]
            },
            "captainBasicInfo": {
                "EquippedWeapon": raw_data["basicInfo"]["weaponSkinShows"],
                "accountId": uid,
                "accountType": raw_data["basicInfo"]["accountType"],
                "badgeCnt": raw_data["basicInfo"]["badgeCnt"],
                "badgeId": str(raw_data["basicInfo"]["badgeId"]),
                "createAt": str(raw_data["basicInfo"]["createAt"]),
                "csMaxRank": raw_data["basicInfo"]["csMaxRank"],
                "csRank": raw_data["basicInfo"]["csRank"],
                "csRankingPoints": raw_data["basicInfo"]["csRankingPoints"],
                "exp": raw_data["basicInfo"]["exp"],
                "lastLoginAt": str(raw_data["basicInfo"]["lastLoginAt"]),
                "level": raw_data["basicInfo"]["level"],
                "liked": raw_data["basicInfo"]["liked"],
                "maxRank": raw_data["basicInfo"]["maxRank"],
                "nickname": raw_data["basicInfo"]["nickname"],
                "rank": raw_data["basicInfo"]["rank"],
                "rankingPoints": raw_data["basicInfo"]["rankingPoints"],
                "region": region.upper(),
                "releaseVersion": raw_data["basicInfo"]["releaseVersion"],
                "seasonId": raw_data["basicInfo"]["seasonId"],
                "showBrRank": raw_data["basicInfo"]["showBrRank"],
                "showCsRank": raw_data["basicInfo"]["showCsRank"],
                "title": raw_data["basicInfo"]["title"]
            },
            "creditScoreInfo": {
                "creditScore": raw_data["creditScoreInfo"]["creditScore"],
                "periodicSummaryEndTime": str(raw_data["creditScoreInfo"]["periodicSummaryEndTime"]),
                "rewardState": 1
            },
            "petInfo": {
                "exp": raw_data["petInfo"]["exp"],
                "id": raw_data["petInfo"]["id"],
                "isSelected": raw_data["petInfo"]["isSelected"],
                "level": raw_data["petInfo"]["level"],
                "selectedSkillId": raw_data["petInfo"]["selectedSkillId"],
                "skinId": raw_data["petInfo"]["skinId"]
            },
            "socialinfo": {
                "AccountLanguage": raw_data["socialInfo"]["language"],
                "AccountSignature": raw_data["socialInfo"]["signature"]
            }
        }

        return jsonify(response)

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
