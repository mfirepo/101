#HLS/HTTP/Secure
import sys
import urllib.request
import urllib.parse
import urllib.error
import xbmcplugin
import xbmcgui
import xbmcaddon
import xbmcvfs
import re
import time
import json
import os
import base64
import xml.etree.ElementTree as ET

try:
    import inputstreamhelper
    HAS_INPUTSTREAM_HELPER = True
except ImportError:
    HAS_INPUTSTREAM_HELPER = False

ADDON = xbmcaddon.Addon()
ADDON_ID = ADDON.getAddonInfo('id')
ADDON_NAME = ADDON.getAddonInfo('name')
ADDON_VERSION = ADDON.getAddonInfo('version')
ADDON_PATH = ADDON.getAddonInfo('path')
PLUGIN_KEY = "plugin.video.paradox"
HANDLE = int(sys.argv[1])

def verify_addon_id():
    addon_xml_path = os.path.join(ADDON_PATH, 'addon.xml')
    try:
        tree = ET.parse(addon_xml_path)
        root = tree.getroot()
        xml_addon_id = root.get('id', '')
        
        if xml_addon_id != ADDON_ID:
            return False
        return True
    except Exception:
        return False

if not verify_addon_id():
    sys.exit()

ADDON_ICON = xbmcvfs.translatePath(f"special://home/addons/{ADDON_ID}/icon.png")
ADDON_FANART = xbmcvfs.translatePath(f"special://home/addons/{ADDON_ID}/fanart.jpg")

CACHE_DIR = xbmcvfs.translatePath(f"special://userdata/addon_data/{ADDON_ID}/")
CACHE_FILE = os.path.join(CACHE_DIR, "playlist_cache.dat")
FAVOURITES_FILE = os.path.join(CACHE_DIR, "encrypted_favourites.dat")
CONFIG_CACHE_FILE = os.path.join(CACHE_DIR, "config_cache.dat")

XOR_KEY = b"k5F9#mR2@qW8!zX0$vB7%nC1^aD3&sE4*lG6(jH0)pK9_yL2"

REMOTE_CONFIG_URL = "https://cmanbuildsxyz.com/neo/para.json"

PLAYLIST_SOURCES = {}
BLOCKED_KEYWORDS = []
TITLE_BLOCK_PATTERNS = []
CACHE_DURATION = 12 * 60 * 60
MAX_TITLE_LENGTH = 40

seen_titles_global = set()

def log(message, level=xbmc.LOGINFO):
    xbmc.log(f"[{ADDON_NAME} v{ADDON_VERSION}] {message}", level)

def load_remote_config(force_refresh=False):
    global PLAYLIST_SOURCES, BLOCKED_KEYWORDS, TITLE_BLOCK_PATTERNS, CACHE_DURATION, MAX_TITLE_LENGTH
    
    if not force_refresh and xbmcvfs.exists(CONFIG_CACHE_FILE):
        try:
            with open(CONFIG_CACHE_FILE, 'rb') as f:
                encrypted_data = f.read()
            
            if encrypted_data:
                decrypted_data = xor_encrypt_decrypt(encrypted_data)
                cache_data = json.loads(decrypted_data.decode('utf-8'))
                
                if time.time() - cache_data.get('timestamp', 0) < 86400:
                    config = cache_data.get('config', {})
                    apply_config(config)
                    log("Loaded configuration from encrypted cache")
                    return True
        except Exception as e:
            log(f"Error loading encrypted config cache: {str(e)}", xbmc.LOGWARNING)
    
    try:
        req = urllib.request.Request(
            REMOTE_CONFIG_URL,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json',
                'Cache-Control': 'no-cache'
            }
        )
        
        with urllib.request.urlopen(req, timeout=30) as response:
            if response.status == 200:
                config_data = response.read().decode('utf-8')
                config = json.loads(config_data)
                
                if not config.get('playlist_sources'):
                    raise ValueError("Remote config missing 'playlist_sources'")
                
                apply_config(config)
                
                ensure_cache_dir()
                cache_data = {
                    'timestamp': time.time(),
                    'config': config
                }
                
                json_data = json.dumps(cache_data).encode('utf-8')
                encrypted_data = xor_encrypt_decrypt(json_data)
                
                with open(CONFIG_CACHE_FILE, 'wb') as f:
                    f.write(encrypted_data)
                
                log("Successfully loaded and encrypted remote configuration")
                return True
            else:
                log(f"Failed to fetch config: HTTP {response.status}", xbmc.LOGERROR)
                return False
                
    except Exception as e:
        log(f"Error loading remote configuration: {str(e)}", xbmc.LOGERROR)
        
        if xbmcvfs.exists(CONFIG_CACHE_FILE):
            try:
                with open(CONFIG_CACHE_FILE, 'rb') as f:
                    encrypted_data = f.read()
                if encrypted_data:
                    decrypted_data = xor_encrypt_decrypt(encrypted_data)
                    cache_data = json.loads(decrypted_data.decode('utf-8'))
                    config = cache_data.get('config', {})
                    apply_config(config)
                    log("Using expired encrypted config cache due to network error")
                    return True
            except Exception as cache_error:
                log(f"Failed to use cached config: {str(cache_error)}", xbmc.LOGERROR)
        
        return False

def apply_config(config):
    global PLAYLIST_SOURCES, BLOCKED_KEYWORDS, TITLE_BLOCK_PATTERNS, CACHE_DURATION, MAX_TITLE_LENGTH
    
    playlist_sources = config.get('playlist_sources', {})
    if not playlist_sources:
        raise ValueError("Playlist sources are required in configuration")
    PLAYLIST_SOURCES = playlist_sources
    
    BLOCKED_KEYWORDS = config.get('blocked_keywords', [])
    
    TITLE_BLOCK_PATTERNS = config.get('title_block_patterns', [])
    
    cache_hours = config.get('cache_duration_hours', 12)
    CACHE_DURATION = cache_hours * 60 * 60
    
    MAX_TITLE_LENGTH = config.get('max_title_length', 40)
    
    log(f"Configuration applied: {len(PLAYLIST_SOURCES)} sources, {len(BLOCKED_KEYWORDS)} blocked keywords")

def ensure_cache_dir():
    if not xbmcvfs.exists(CACHE_DIR):
        xbmcvfs.mkdirs(CACHE_DIR)

def xor_encrypt_decrypt(data):
    if XOR_KEY is None:
        log("XOR_KEY not initialized!", xbmc.LOGERROR)
        return data
    
    key_length = len(XOR_KEY)
    return bytes([data[i] ^ XOR_KEY[i % key_length] for i in range(len(data))])

def encrypt_favourite_url(url):
    url_bytes = url.encode('utf-8')
    encrypted_bytes = xor_encrypt_decrypt(url_bytes)
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def decrypt_favourite_url(encrypted_url):
    try:
        encrypted_bytes = base64.b64decode(encrypted_url.encode('utf-8'))
        decrypted_bytes = xor_encrypt_decrypt(encrypted_bytes)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        log(f"Error decrypting favourite URL: {str(e)}", xbmc.LOGERROR)
        return None

def load_cache():
    ensure_cache_dir()
    if not xbmcvfs.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, 'rb') as f:
            encrypted_data = f.read()
        if not encrypted_data:
            return {}
        decrypted_data = xor_encrypt_decrypt(encrypted_data)
        cache_data = json.loads(decrypted_data.decode('utf-8'))
        current_time = time.time()
        cleaned_cache = {}
        for source_name, cache_entry in cache_data.items():
            if current_time - cache_entry.get('timestamp', 0) <= CACHE_DURATION:
                cleaned_cache[source_name] = cache_entry
        if len(cleaned_cache) != len(cache_data):
            save_cache(cleaned_cache)
        return cleaned_cache
    except Exception as e:
        log(f"Error loading cache: {str(e)}", xbmc.LOGERROR)
        return {}

def save_cache(cache_data):
    try:
        ensure_cache_dir()
        json_data = json.dumps(cache_data).encode('utf-8')
        encrypted_data = xor_encrypt_decrypt(json_data)
        with open(CACHE_FILE, 'wb') as f:
            f.write(encrypted_data)
    except Exception as e:
        log(f"Error saving cache: {str(e)}", xbmc.LOGERROR)

def get_cached_channels(source_name):
    cache_data = load_cache()
    if source_name in cache_data:
        cache_entry = cache_data[source_name]
        if time.time() - cache_entry.get('timestamp', 0) <= CACHE_DURATION:
            return cache_entry.get('channels', [])
    return None

def cache_channels(source_name, channels):
    cache_data = load_cache()
    cache_data[source_name] = {'timestamp': time.time(), 'channels': channels}
    save_cache(cache_data)

def clear_cache():
    files_cleared = []
    
    if xbmcvfs.exists(CACHE_FILE):
        xbmcvfs.delete(CACHE_FILE)
        files_cleared.append("Playlist cache")
        log("Cleared playlist cache")
    
    if xbmcvfs.exists(CONFIG_CACHE_FILE):
        xbmcvfs.delete(CONFIG_CACHE_FILE)
        files_cleared.append("Configuration cache")
        log("Cleared configuration cache")
    
    if files_cleared:
        log(f"Cleared cache files: {', '.join(files_cleared)}")
        return True
    else:
        log("No cache files found to clear")
        return False

def get_url(**kwargs):
    return f"{sys.argv[0]}?{urllib.parse.urlencode(kwargs)}"

def get_encrypted_play_url(url):
    encrypted_url = encrypt_favourite_url(url)
    return get_url(action='play_encrypted', encrypted_url=encrypted_url)

def contains_blocked_keywords(title):
    if not title:
        return False
    title_lower = title.lower()
    for keyword in BLOCKED_KEYWORDS:
        if keyword.lower() in title_lower:
            return True
    return False

def contains_ascii_characters(title):
    if not title:
        return False
    try:
        title.encode('ascii')
        return False
    except (UnicodeEncodeError, UnicodeDecodeError):
        return True

def contains_at_character(title):
    if not title:
        return False
    if '@' in title:
        return True
    return False

def contains_blocked_patterns(title):
    if not title:
        return False
    for pattern in TITLE_BLOCK_PATTERNS:
        if re.search(pattern, title):
            return True
    return False

def exceeds_character_limit(title):
    if not title:
        return False
    return len(title.strip()) > MAX_TITLE_LENGTH

def should_skip_channel(title):
    if not title:
        return True
    if contains_blocked_keywords(title):
        return True
    if contains_ascii_characters(title):
        return True
    if contains_at_character(title):
        return True
    if contains_blocked_patterns(title):
        return True
    if exceeds_character_limit(title):
        return True
    skip_patterns = [r'^\d{1,2}:\d{2}', r'^\d{4}-\d{2}-\d{2}', r'https?://', r'\.(jpg|jpeg|png|gif|bmp|webp)$', r'^\s*$']
    title_lower = title.lower() if title else ""
    for pattern in skip_patterns:
        if re.search(pattern, title_lower):
            return True
    if len(title.strip()) < 3:
        return True
    return False

def clean_title(title):
    if not title:
        return title
    title = re.sub(r'\([^)]*\)', '', title)
    title = re.sub(r'\[[^\]]*\]', '', title)
    
    title = re.sub(r'\.(ts|m3u8|mp4|avi|mkv|jpg|jpeg|png|gif)$', '', title, flags=re.IGNORECASE)
    
    title = re.sub(r'\[[^\]]*?(?:HD|SD|FHD|UHD|4K|1080|720|480)[^\]]*?\]', '', title, flags=re.IGNORECASE)
    title = re.sub(r'\([^\)]*?(?:HD|SD|FHD|UHD|4K|1080|720|480)[^\)]*?\)', '', title, flags=re.IGNORECASE)
    title = re.sub(r'\b(?:HD|SD|FHD|UHD|4K|1080p|720p|480p)\b', '', title, flags=re.IGNORECASE)
    
    title = re.sub(r'\s+', ' ', title).strip()
    title = re.sub(r'[\s\-:\|]+$', '', title)
    title = re.sub(r'^[\s\-:\|]+', '', title)
    
    return title

def get_stream_headers(url):
    url_lower = url.lower()
    
    if 'a1xs.vip' in url_lower or 'https://a1xs.vip/' in url:
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Referer': 'https://a1xs.vip/',
            'Origin': 'https://a1xs.vip',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'DNT': '1',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache'
        }
    
    elif 'jmp2.uk' in url_lower or 'https://jmp2.uk/' in url:
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'identity',
            'Referer': 'https://jmp2.uk/',
            'Origin': 'https://jmp2.uk',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'video',
            'Sec-Fetch-Mode': 'no-cors',
            'Sec-Fetch-Site': 'same-site',
            'DNT': '1',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'Range': 'bytes=0-'
        }
    
    else:
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache'
        }

def fetch_playlist_content(url):
    try:
        headers = get_stream_headers(url)
        
        req = urllib.request.Request(
            url,
            headers=headers
        )
        
        with urllib.request.urlopen(req, timeout=20) as response:
            if response.status == 200:
                return response.read().decode('utf-8')
            else:
                return None
    except Exception as e:
        log(f"Error fetching playlist: {str(e)}", xbmc.LOGERROR)
        return None

def parse_m3u_playlist(content, source_name=""):
    if not content:
        return []
    channels = []
    lines = content.split('\n')
    current_channel = {}
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith('#EXTM3U') or line.startswith('#EXTVLCOPT'):
            continue
        
        if line.startswith('#EXTINF:'):
            parts = line.split(',', 1)
            if len(parts) > 1:
                title = parts[1].strip()
                title = clean_title(title)
                if should_skip_channel(title):
                    current_channel = {}
                    continue
                current_channel = {'title': title, 'source': source_name}
        
        elif (line.startswith('http') or line.startswith('https')) and current_channel:
            current_channel['url'] = line
            current_channel['thumbnail'] = ADDON_ICON
            current_channel['fanart'] = ADDON_FANART
            channels.append(current_channel)
            current_channel = {}
    
    return channels

def get_channels_from_source(source_name, force_refresh=False):
    global seen_titles_global
    seen_titles_global = set()
    
    if not force_refresh:
        cached_channels = get_cached_channels(source_name)
        if cached_channels is not None:
            return cached_channels
    
    playlist_url = PLAYLIST_SOURCES.get(source_name)
    if not playlist_url:
        return []
    
    content = fetch_playlist_content(playlist_url)
    if content:
        channels = parse_m3u_playlist(content, source_name)
        filtered_channels = []
        
        for channel in channels:
            title = channel['title']
            title_lower = title.lower()
            
            if (contains_blocked_keywords(title) or 
                contains_ascii_characters(title) or 
                contains_at_character(title) or 
                contains_blocked_patterns(title) or 
                title_lower in seen_titles_global):
                continue
            
            seen_titles_global.add(title_lower)
            filtered_channels.append(channel)
        
        cache_channels(source_name, filtered_channels)
        return filtered_channels
    else:
        cached_channels = get_cached_channels(source_name)
        if cached_channels:
            return cached_channels
        return []

def detect_stream_type(url):
    url_lower = url.lower()
    
    if 'a1xs.vip' in url_lower:
        stream_type = 'hls'
        prefix = 'a1xs'
    elif 'jmp2.uk' in url_lower:
        stream_type = 'hls'
        prefix = 'jmp2'
    elif '.m3u8' in url_lower or 'hls' in url_lower:
        stream_type = 'hls'
        prefix = 'generic'
    elif '.mpd' in url_lower or 'dash' in url_lower:
        stream_type = 'dash'
        prefix = 'generic'
    elif '.mp4' in url_lower or 'mp4' in url_lower:
        stream_type = 'mp4'
        prefix = 'generic'
    elif 'm3u8' in url_lower or 'live' in url_lower or 'stream' in url_lower:
        stream_type = 'hls'
        prefix = 'generic'
    else:
        stream_type = 'http'
        prefix = 'generic'
    
    return stream_type, prefix

def setup_inputstream(list_item, url, stream_type='hls', prefix='generic'):
    if not HAS_INPUTSTREAM_HELPER:
        return False
    
    headers = get_stream_headers(url)
    headers_str = '&'.join([f'{k}={urllib.parse.quote(v)}' for k, v in headers.items()])
    
    if stream_type == 'hls':
        is_helper = inputstreamhelper.Helper('hls')
        if is_helper.check_inputstream():
            list_item.setProperty('inputstream', 'inputstream.adaptive')
            list_item.setProperty('inputstream.adaptive.manifest_type', 'hls')
            list_item.setProperty('inputstream.adaptive.manifest_update_parameter', 'full')
            list_item.setProperty('inputstream.adaptive.stream_headers', headers_str)
            
            if prefix == 'a1xs':
                list_item.setProperty('inputstream.adaptive.manifest_headers', headers_str)
                list_item.setProperty('inputstream.adaptive.license_flags', 'persistent_storage')
                list_item.setProperty('inputstream.adaptive.license_type', 'com.widevine.alpha')
            elif prefix == 'jmp2':
                list_item.setProperty('inputstream.adaptive.manifest_headers', headers_str)
                list_item.setProperty('inputstream.adaptive.stream_headers', headers_str)
                list_item.setContentLookup(False)
            
            return True
    
    elif stream_type == 'dash':
        is_helper = inputstreamhelper.Helper('mpd')
        if is_helper.check_inputstream():
            list_item.setProperty('inputstream', 'inputstream.adaptive')
            list_item.setProperty('inputstream.adaptive.manifest_type', 'mpd')
            list_item.setProperty('inputstream.adaptive.stream_headers', headers_str)
            return True
    
    return False

def play_channel(url):
    try:
        stream_type, prefix = detect_stream_type(url)
        headers = get_stream_headers(url)
        
        list_item = xbmcgui.ListItem(path=url)
        list_item.setProperty('IsPlayable', 'true')
        
        if stream_type == 'hls':
            list_item.setMimeType('application/vnd.apple.mpegurl')
            list_item.setContentLookup(False)
            setup_inputstream(list_item, url, 'hls', prefix)
        elif stream_type == 'dash':
            list_item.setMimeType('application/dash+xml')
            setup_inputstream(list_item, url, 'dash', prefix)
        elif stream_type == 'mp4':
            list_item.setMimeType('video/mp4')
        else:
            list_item.setMimeType('video/mp4')
        
        headers_str = '&'.join([f'{k}={urllib.parse.quote(v)}' for k, v in headers.items()])
        list_item.setProperty('inputstream.adaptive.stream_headers', headers_str)
        
        if prefix == 'a1xs':
            list_item.setProperty('inputstream.adaptive.license_flags', 'persistent_storage')
            list_item.setProperty('inputstream.adaptive.license_type', 'com.widevine.alpha')
        elif prefix == 'jmp2':
            list_item.setProperty('inputstreamaddon', 'inputstream.adaptive')
            list_item.setProperty('inputstream.adaptive.manifest_headers', headers_str)
        
        xbmcplugin.setResolvedUrl(HANDLE, True, list_item)
        return True
    except Exception as e:
        xbmcgui.Dialog().ok('Playback Error', f'Unable to play stream: {str(e)}', 'The stream may be unavailable or require special handling.')
        xbmcplugin.setResolvedUrl(HANDLE, False, xbmcgui.ListItem())
        return False

def play_encrypted_channel(encrypted_url):
    decrypted_url = decrypt_favourite_url(encrypted_url)
    if decrypted_url:
        return play_channel(decrypted_url)
    else:
        xbmcgui.Dialog().ok('Error', 'Could not decrypt stream URL.')
        return False

def save_custom_favourite(channel_title, channel_url, source_name):
    ensure_cache_dir()
    favourites = load_custom_favourites()
    favourite_id = f"{source_name}_{channel_title}_{int(time.time())}"
    
    favourites[favourite_id] = {
        'title': channel_title,
        'encrypted_url': encrypt_favourite_url(channel_url),
        'source': source_name,
        'thumbnail': ADDON_ICON,
        'fanart': ADDON_FANART,
        'timestamp': time.time(),
        'last_updated': time.time()
    }
    
    try:
        with open(FAVOURITES_FILE, 'w') as f:
            json.dump(favourites, f)
        return True
    except Exception as e:
        log(f"Error saving favourite: {str(e)}", xbmc.LOGERROR)
        return False

def load_custom_favourites():
    if not xbmcvfs.exists(FAVOURITES_FILE):
        return {}
    try:
        with open(FAVOURITES_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        log(f"Error loading favourites: {str(e)}", xbmc.LOGERROR)
        return {}

def remove_custom_favourite(favourite_id):
    favourites = load_custom_favourites()
    if favourite_id in favourites:
        del favourites[favourite_id]
        try:
            with open(FAVOURITES_FILE, 'w') as f:
                json.dump(favourites, f)
            return True
        except Exception as e:
            log(f"Error removing favourite: {str(e)}", xbmc.LOGERROR)
    return False

def update_favourite_urls():
    favourites = load_custom_favourites()
    updated_count = 0
    
    for fav_id, favourite in favourites.items():
        source_name = favourite.get('source')
        channel_title = favourite.get('title')
        
        if not source_name or not channel_title:
            continue
        
        current_channels = get_channels_from_source(source_name, force_refresh=False)
        matching_channel = None
        
        for channel in current_channels:
            if channel.get('title') == channel_title:
                matching_channel = channel
                break
        
        if matching_channel and matching_channel.get('url'):
            new_url = matching_channel['url']
            current_encrypted = favourite.get('encrypted_url')
            current_decrypted = decrypt_favourite_url(current_encrypted) if current_encrypted else None
            
            if new_url != current_decrypted:
                favourites[fav_id]['encrypted_url'] = encrypt_favourite_url(new_url)
                favourites[fav_id]['last_updated'] = time.time()
                updated_count += 1
    
    if updated_count > 0:
        try:
            with open(FAVOURITES_FILE, 'w') as f:
                json.dump(favourites, f)
        except Exception as e:
            log(f"Error updating favourites: {str(e)}", xbmc.LOGERROR)
    
    return updated_count

def get_smart_favourite_url(favourite):
    encrypted_url = favourite.get('encrypted_url')
    if encrypted_url:
        decrypted_url = decrypt_favourite_url(encrypted_url)
        if decrypted_url:
            return decrypted_url
    return None

def show_custom_favourites():
    update_favourite_urls()
    favourites = load_custom_favourites()
    
    if not favourites:
        xbmcgui.Dialog().ok('No Favourites', 'You haven\'t added any favourites yet.')
        return
    
    for fav_id, favourite in favourites.items():
        title = favourite.get('title', 'Unknown Channel')
        source = favourite.get('source', 'Unknown Source')
        last_updated = favourite.get('last_updated', 0)
        current_url = get_smart_favourite_url(favourite)
        
        if not current_url:
            title = f"[COLOR red]{title} (Broken)[/COLOR]"
        
        list_item = xbmcgui.ListItem(label=title)
        list_item.setArt({
            'thumb': favourite.get('thumbnail', ADDON_ICON),
            'icon': favourite.get('thumbnail', ADDON_ICON),
            'fanart': favourite.get('fanart', ADDON_FANART)
        })
        
        last_update_str = time.strftime('%Y-%m-%d %H:%M', time.localtime(last_updated))
        plot = f'Favourite: {title}\nSource: {source}\nLast Updated: {last_update_str}'
        
        if not current_url:
            plot += '\n[COLOR red]URL not found in current source[/COLOR]'
        
        list_item.setInfo('video', {
            'title': title,
            'plot': plot,
            'genre': 'Favourite'
        })
        
        if current_url:
            list_item.setProperty('IsPlayable', 'true')
        
        context_menu = [
            ('Remove Favourite', f'RunPlugin({get_url(action="remove_favourite", fav_id=fav_id)})'),
            ('Update This Favourite', f'RunPlugin({get_url(action="update_single_favourite", fav_id=fav_id)})')
        ]
        list_item.addContextMenuItems(context_menu)
        
        if current_url:
            plugin_url = get_url(action='play_favourite', encrypted_url=favourite.get('encrypted_url'))
        else:
            plugin_url = get_url(action='noop')
        
        xbmcplugin.addDirectoryItem(HANDLE, plugin_url, list_item, isFolder=False)
    
    xbmcplugin.setContent(HANDLE, 'videos')
    xbmcplugin.endOfDirectory(HANDLE)

def update_single_favourite(fav_id):
    favourites = load_custom_favourites()
    if fav_id not in favourites:
        return False
    
    favourite = favourites[fav_id]
    source_name = favourite.get('source')
    channel_title = favourite.get('title')
    
    current_channels = get_channels_from_source(source_name, force_refresh=True)
    matching_channel = None
    
    for channel in current_channels:
        if channel.get('title') == channel_title:
            matching_channel = channel
            break
    
    if matching_channel and matching_channel.get('url'):
        new_url = matching_channel['url']
        favourites[fav_id]['encrypted_url'] = encrypt_favourite_url(new_url)
        favourites[fav_id]['last_updated'] = time.time()
        
        try:
            with open(FAVOURITES_FILE, 'w') as f:
                json.dump(favourites, f)
            return True
        except Exception as e:
            log(f"Error updating single favourite: {str(e)}", xbmc.LOGERROR)
    
    return False

def play_encrypted_favourite(encrypted_url):
    decrypted_url = decrypt_favourite_url(encrypted_url)
    if decrypted_url:
        return play_channel(decrypted_url)
    else:
        xbmcgui.Dialog().ok('Error', 'Could not decrypt favourite URL. It may be corrupted.')
        return False

def show_landing_page():
    global seen_titles_global
    seen_titles_global = set()
    
    for source_name in PLAYLIST_SOURCES.keys():
        list_item = xbmcgui.ListItem(label=source_name)
        list_item.setArt({
            'thumb': ADDON_ICON,
            'icon': ADDON_ICON,
            'fanart': ADDON_FANART
        })
        list_item.setInfo('video', {
            'title': source_name,
            'plot': f'Browse channels from {source_name} only'
        })
        xbmcplugin.addDirectoryItem(
            HANDLE,
            get_url(action='source', source=source_name),
            list_item,
            isFolder=True
        )
    
    list_item = xbmcgui.ListItem(label="[COLORlime]My Favourites[/COLOR]")
    list_item.setArt({
        'thumb': ADDON_ICON,
        'icon': ADDON_ICON,
        'fanart': ADDON_FANART
    })
    list_item.setInfo('video', {
        'title': 'Paradox Favourites',
        'plot': 'Your saved favourite channels'
    })
    xbmcplugin.addDirectoryItem(
        HANDLE,
        get_url(action='show_favourites'),
        list_item,
        isFolder=True
    )
    
    list_item = xbmcgui.ListItem(label="[COLOR lime]Refresh Lists[/COLOR]")
    list_item.setArt({
        'thumb': ADDON_ICON,
        'icon': ADDON_ICON,
        'fanart': ADDON_FANART
    })
    list_item.setInfo('video', {
        'title': 'Refresh Playlists And Clear Cache',
        'plot': 'Clear playlist and configuration cache (favourites will be preserved)'
    })
    xbmcplugin.addDirectoryItem(
        HANDLE,
        get_url(action='clear_cache'),
        list_item,
        isFolder=False
    )
    
    xbmcplugin.setContent(HANDLE, 'files')
    xbmcplugin.endOfDirectory(HANDLE)

def list_source_channels(source_name, force_refresh=False):
    channels = get_channels_from_source(source_name, force_refresh)
    
    if not channels:
        xbmcgui.Dialog().ok('Error', f'No channels found from {source_name}. Please check your internet connection and try again.')
        xbmcplugin.endOfDirectory(HANDLE)
        return
    
    channels.sort(key=lambda x: x['title'].lower())
    
    for channel in channels:
        title = channel.get('title', 'Unknown Channel')
        url = channel.get('url', '')
        thumbnail = channel.get('thumbnail', ADDON_ICON)
        
        list_item = xbmcgui.ListItem(label=title)
        list_item.setArt({
            'thumb': thumbnail,
            'icon': thumbnail,
            'fanart': ADDON_FANART
        })
        
        stream_type, prefix = detect_stream_type(url)
        list_item.setInfo('video', {
            'title': title,
            'plot': f'Live TV Channel: {title}\nSource: {source_name}\nStream Type: {stream_type.upper()}'
        })
        
        list_item.setProperty('IsPlayable', 'true')
        encrypted_plugin_url = get_encrypted_play_url(url)
        
        context_menu = [(
            'Add To My Favourites',
            f'RunPlugin({get_url(action="add_favourite", title=urllib.parse.quote(title), url=urllib.parse.quote(url), source=source_name)})'
        )]
        
        list_item.addContextMenuItems(context_menu)
        xbmcplugin.addDirectoryItem(HANDLE, encrypted_plugin_url, list_item, isFolder=False)
    
    xbmcplugin.setContent(HANDLE, 'videos')
    xbmcplugin.endOfDirectory(HANDLE)

def router(params):
    action = params.get('action', '')
    url = params.get('url', '')
    source = params.get('source', '')
    force_refresh = params.get('refresh', '') == 'true'
    fav_id = params.get('fav_id', '')
    encrypted_url = params.get('encrypted_url', '')
    title = params.get('title', '')
    
    if action == 'play' and url:
        play_channel(urllib.parse.unquote(url))
    
    elif action == 'play_encrypted' and encrypted_url:
        play_encrypted_channel(encrypted_url)
    
    elif action == 'play_favourite' and encrypted_url:
        play_encrypted_favourite(encrypted_url)
    
    elif action == 'source' and source:
        list_source_channels(source, force_refresh)
    
    elif action == 'clear_cache':
        if clear_cache():
            xbmcgui.Dialog().ok('Information', 'Playlists refreshed and configuration cache cleared.\n\nYour favourites have been preserved.')
        show_landing_page()
    
    elif action == 'show_favourites':
        show_custom_favourites()
    
    elif action == 'add_favourite' and url and title:
        decoded_title = urllib.parse.unquote(title)
        save_custom_favourite(decoded_title, urllib.parse.unquote(url), source)
        xbmcgui.Dialog().notification('Favourite Added', f'Added {decoded_title} to favourites', ADDON_ICON, 3000)
    
    elif action == 'remove_favourite' and fav_id:
        if remove_custom_favourite(fav_id):
            xbmcgui.Dialog().notification('Favourite Removed', 'Favourite removed successfully', ADDON_ICON, 3000)
        show_custom_favourites()
    
    elif action == 'update_single_favourite' and fav_id:
        update_single_favourite(fav_id)
        show_custom_favourites()
    
    elif action == 'noop':
        pass
    
    else:
        show_landing_page()

if __name__ == '__main__':
    if not load_remote_config():
        xbmcgui.Dialog().ok(
            'Configuration Error',
            'Failed to load encrypted configuration from remote server.',
            'The addon cannot function without a valid configuration.',
            'Please check your internet connection and try again.'
        )
        xbmcplugin.endOfDirectory(HANDLE)
    else:
        params = dict(urllib.parse.parse_qsl(sys.argv[2][1:]))
        router(params)
