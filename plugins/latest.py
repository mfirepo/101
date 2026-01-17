#NeoFlix_Enhanced_Playback
import os, time, json, base64, sqlite3, hashlib, urllib.parse, urllib.request
import xml.etree.ElementTree as ET, xbmc, xbmcvfs, xbmcgui, xbmcplugin, xbmcaddon, sys, resolveurl, re

ADDON = xbmcaddon.Addon()
ADDON_ID = ADDON.getAddonInfo('id')
ADDON_NAME = ADDON.getAddonInfo('name')
ADDON_VERSION = ADDON.getAddonInfo('version')
ADDON_PATH = ADDON.getAddonInfo('path')
PLUGIN_KEY = "plugin.video.neo_flix"
HANDLE = int(sys.argv[1])

SECURITY_XML_MD5_HASH = "9024aa9e2d9f0c414e8c99a8fddb770b"
REQUIRED_REPO_IDS = ["repository.cMaNWizard", "repository.madforit"]
REQUIRED_REPO_NAME = "cMans Repo"
SECURITY_XML_URL = "https://raw.githubusercontent.com/mfirepo/101/main/neosecurity.xml"
SECURITY_CACHE_TIME = 86400

SUBLIST_CACHE_TIME = 86400
SUBLIST_CACHE_DIR = xbmcvfs.translatePath(f"special://temp/{ADDON_ID}_cache/")
SECURITY_CACHE_FILE = xbmcvfs.translatePath(f"special://home/addons/{ADDON_ID}/security_cache.xml")
LOCAL_JSON_PATH = xbmcvfs.translatePath(f"special://home/addons/{ADDON_ID}/resources/data.json")

ADDON_ICON = xbmcvfs.translatePath(f"special://home/addons/{ADDON_ID}/icon.png")
ADDON_FANART = xbmcvfs.translatePath(f"special://home/addons/{ADDON_ID}/fanart.jpg")
OBFUSCATED_JSON_KEY = PLUGIN_KEY + "json_encryption_key"

def log(message, level=xbmc.LOGINFO):
    xbmc.log(f"[{ADDON_NAME} v{ADDON_VERSION}] {message}", level)

def get_url(**kwargs):
    return f"{sys.argv[0]}?{urllib.parse.urlencode(kwargs)}"

def ensure_directory(path):
    if not xbmcvfs.exists(path):
        xbmcvfs.mkdirs(path)
        return True
    return False

def encrypt(text, key):
    try:
        encrypted_bytes = bytes([ord(c) ^ ord(key[i % len(key)]) for i, c in enumerate(text)])
        return base64.urlsafe_b64encode(encrypted_bytes).decode()
    except Exception as e:
        log(f"Encryption error: {str(e)}", xbmc.LOGERROR)
        return ""

def decrypt(encrypted_text, key):
    try:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_text.encode())
        decrypted_chars = [chr(b ^ ord(key[i % len(key)])) for i, b in enumerate(encrypted_bytes)]
        return ''.join(decrypted_chars)
    except Exception as e:
        log(f"Decryption error: {str(e)}", xbmc.LOGERROR)
        return ""

class SecurityManager:
    def calculate_md5_hash(self, content):
        return hashlib.md5(content.encode('utf-8')).hexdigest() if content else None
    
    def verify_security_xml_hash(self, xml_content):
        if not SECURITY_XML_MD5_HASH or SECURITY_XML_MD5_HASH == "YOUR_SECURITY_XML_MD5_HASH_HERE":
            return False
        return self.calculate_md5_hash(xml_content) == SECURITY_XML_MD5_HASH
    
    def verify_repository_installed(self):
        addons_path = xbmcvfs.translatePath("special://home/addons/")
        for repo_id in REQUIRED_REPO_IDS:
            if xbmcvfs.exists(os.path.join(addons_path, repo_id)):
                return True
        
        try:
            db_path = xbmcvfs.translatePath("special://database/Addons33.db")
            if xbmcvfs.exists(db_path):
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                placeholders = ','.join('?' * len(REQUIRED_REPO_IDS))
                cursor.execute(f"SELECT addonID FROM installed WHERE addonID IN ({placeholders})", REQUIRED_REPO_IDS)
                result = cursor.fetchone()
                conn.close()
                if result: return True
        except: pass
        
        repos_xml_path = xbmcvfs.translatePath("special://home/addons/repositories.xml")
        if xbmcvfs.exists(repos_xml_path):
            try:
                with xbmcvfs.File(repos_xml_path, 'r') as f:
                    xml_content = f.read()
                if xml_content:
                    root = ET.fromstring(xml_content)
                    for repo in root.findall(".//info"):
                        if repo.get("id") in REQUIRED_REPO_IDS:
                            return True
            except: pass
        return False
    
    def show_repository_required_message(self):
        xbmcgui.Dialog().ok("Repository Required", f"{ADDON_NAME} requires {REQUIRED_REPO_NAME} to function properly.\n\nPlease install the repository ZIP file to access content.")
    
    def is_playback_allowed(self):
        return self.verify_repository_installed()
    
    def fetch_security_xml(self):
        try:
            req = urllib.request.Request(SECURITY_XML_URL, headers={'User-Agent': f'{ADDON_NAME}/{ADDON_VERSION} (Kodi)'})
            with urllib.request.urlopen(req, timeout=15) as response:
                if response.status == 200:
                    return response.read().decode()
            return None
        except Exception as e:
            log(f"Error fetching security XML: {str(e)}", xbmc.LOGERROR)
            return None
    
    def validate_security_xml(self, xml_content):
        try:
            if not xml_content or not self.verify_security_xml_hash(xml_content):
                return False
            root = ET.fromstring(xml_content)
            for addon_elem in root.findall('.//addon'):
                if addon_elem.get('id') == ADDON_ID:
                    return addon_elem.get('status', 'enabled') == 'enabled'
            return False
        except Exception as e:
            log(f"Error validating security XML: {str(e)}", xbmc.LOGERROR)
            return False
    
    def check_cached_security(self):
        try:
            if xbmcvfs.exists(SECURITY_CACHE_FILE):
                cache_time = os.path.getmtime(SECURITY_CACHE_FILE)
                if time.time() - cache_time < SECURITY_CACHE_TIME:
                    with xbmcvfs.File(SECURITY_CACHE_FILE, 'r') as f:
                        xml_content = f.read()
                    if self.validate_security_xml(xml_content):
                        return True
        except: pass
        return False
    
    def cache_security_validation(self, xml_content):
        try:
            with xbmcvfs.File(SECURITY_CACHE_FILE, 'w') as f:
                f.write(xml_content)
        except Exception as e:
            log(f"Error caching security validation: {str(e)}", xbmc.LOGERROR)
    
    def execute_security_validation(self):
        if self.check_cached_security():
            return True
        xml_content = self.fetch_security_xml()
        if not xml_content:
            xbmcgui.Dialog().ok('Connection Error', 'Could not contact authorization server.')
            return False
        if not self.validate_security_xml(xml_content):
            xbmcgui.Dialog().ok('Authorization Error', 'This addon is not authorized to function.')
            return False
        self.cache_security_validation(xml_content)
        return True
    
    def is_security_valid(self):
        try:
            return self.execute_security_validation()
        except Exception as e:
            log(f"Security validation error: {str(e)}", xbmc.LOGERROR)
            xbmcgui.Dialog().ok('Security Error', 'An error occurred during security verification.')
            return False

class CacheManager:
    def __init__(self):
        ensure_directory(SUBLIST_CACHE_DIR)
    
    def get_sublist_cache_filename(self, url):
        return os.path.join(SUBLIST_CACHE_DIR, f"{hashlib.md5(url.encode('utf-8')).hexdigest()}.cache")
    
    def get_cached_sublist(self, url):
        try:
            cache_file = self.get_sublist_cache_filename(url)
            if not xbmcvfs.exists(cache_file):
                return None
            if time.time() - os.path.getmtime(cache_file) > SUBLIST_CACHE_TIME:
                return None
            with xbmcvfs.File(cache_file, 'r') as f:
                encrypted_cache = f.read()
            if not encrypted_cache:
                return None
            decrypted_cache = decrypt(encrypted_cache, PLUGIN_KEY)
            return json.loads(decrypted_cache) if decrypted_cache else None
        except:
            return None
    
    def cache_sublist(self, url, data):
        try:
            cache_file = self.get_sublist_cache_filename(url)
            encrypted_cache = encrypt(json.dumps(data), PLUGIN_KEY)
            with xbmcvfs.File(cache_file, 'w') as f:
                f.write(encrypted_cache)
        except Exception as e:
            log(f"Error caching sublist: {str(e)}", xbmc.LOGERROR)
    
    def clear_cache_safe(self):
        try:
            files_deleted = 0
            cache_cleared = False
            if xbmcvfs.exists(SUBLIST_CACHE_DIR):
                dirs, files = xbmcvfs.listdir(SUBLIST_CACHE_DIR)
                for file in files:
                    if file.endswith('.cache'):
                        try:
                            if xbmcvfs.delete(os.path.join(SUBLIST_CACHE_DIR, file)):
                                files_deleted += 1
                                cache_cleared = True
                            xbmc.sleep(100)
                        except: continue
            if xbmcvfs.exists(SECURITY_CACHE_FILE):
                try:
                    if xbmcvfs.delete(SECURITY_CACHE_FILE):
                        files_deleted += 1
                        cache_cleared = True
                except: pass
            if cache_cleared:
                xbmcgui.Dialog().notification('Cache Cleared', f'Deleted {files_deleted} cache files', ADDON_ICON, 2000)
            else:
                xbmcgui.Dialog().notification('Cache Info', 'No cache files found', ADDON_ICON, 2000)
            return cache_cleared
        except Exception as e:
            log(f"Error during safe cache clearing: {str(e)}", xbmc.LOGERROR)
            xbmcgui.Dialog().notification('Cache Error', 'Failed to clear some cache files', xbmcgui.NOTIFICATION_WARNING, 2000)
            return False

class PlaybackManager:
    def __init__(self):
        self.security_manager = SecurityManager()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36'
        ]
    
    def get_rotated_user_agent(self):
        return self.user_agents[int(time.time()) % len(self.user_agents)]
    
    def setup_robust_inputstream(self, list_item, url):
        list_item.setProperty('inputstream', 'inputstream.adaptive')
        list_item.setProperty('inputstream.adaptive.manifest_type', 'hls')
        list_item.setProperty('inputstream.adaptive.manifest_update_parameter', 'full')
        list_item.setProperty('inputstream.adaptive.license_flags', 'persistent_storage')
        list_item.setProperty('inputstream.adaptive.license_type', 'com.widevine.alpha')
        list_item.setProperty('inputstream.adaptive.connection_timeout', '60')
        list_item.setProperty('inputstream.adaptive.manifest_timeout', '60')
        list_item.setProperty('inputstream.adaptive.live_delay', '3')
        list_item.setProperty('inputstream.adaptive.max_bandwidth', '12000000')
        list_item.setProperty('inputstream.adaptive.network_caching', '20000')
        list_item.setProperty('inputstream.adaptive.segment_download_retries', '10')
        list_item.setProperty('inputstream.adaptive.segment_download_timeout', '45')
        
        # Enhanced settings for specific domains
        if 'jmp2.uk' in url or 'a1xs.vip' in url:
            headers = 'User-Agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36&Referer=https://a1xs.vip/&Origin=https://a1xs.vip&Accept=*/*&Accept-Language=en-US,en;q=0.9&Accept-Encoding=identity&Cache-Control=no-cache&Connection=keep-alive&Pragma=no-cache'
            
            list_item.setProperty('inputstream.adaptive.stream_headers', headers)
            list_item.setProperty('inputstream.adaptive.manifest_headers', headers)
            list_item.setProperty('inputstream.adaptive.segment_headers', headers)
            list_item.setProperty('inputstream.adaptive.license_headers', headers)
            list_item.setProperty('inputstream.adaptive.ignore_display_width', 'true')
            list_item.setProperty('inputstream.adaptive.ignore_display_height', 'true')
            list_item.setProperty('inputstream.adaptive.allow_video_switching', 'false')
            list_item.setProperty('inputstream.adaptive.manifest_ttl', '3600')
            list_item.setProperty('inputstream.adaptive.play_timeshift_buffer', 'true')
        
        return True
    
    def get_refreshed_stream(self, base_url, max_retries=5):
        for attempt in range(max_retries):
            try:
                timestamp = int(time.time())
                # Don't add timestamp if it's already there
                if '?_t=' in base_url or '&_t=' in base_url:
                    refreshed_url = base_url
                else:
                    refreshed_url = f"{base_url}{'&' if '?' in base_url else '?'}_t={timestamp}"
                
                # Special handling for specific domains
                if 'jmp2.uk' in base_url or 'a1xs.vip' in base_url:
                    domain = 'jmp2.uk' if 'jmp2.uk' in base_url else 'a1xs.vip'
                    headers = {
                        'User-Agent': self.get_rotated_user_agent(),
                        'Accept': '*/*',
                        'Accept-Language': 'en-US,en;q=0.9',
                        'Accept-Encoding': 'identity',
                        'Cache-Control': 'no-cache',
                        'Connection': 'keep-alive',
                        'Pragma': 'no-cache',
                        'Referer': f'https://{domain}/',
                        'Origin': f'https://{domain}',
                        'Sec-Fetch-Dest': 'empty',
                        'Sec-Fetch-Mode': 'cors',
                        'Sec-Fetch-Site': 'same-origin'
                    }
                else:
                    headers = {
                        'User-Agent': self.get_rotated_user_agent(),
                        'Accept': '*/*',
                        'Cache-Control': 'no-cache'
                    }
                
                log(f"Testing stream URL: {refreshed_url[:100]}...", xbmc.LOGDEBUG)
                req = urllib.request.Request(refreshed_url, headers=headers)
                with urllib.request.urlopen(req, timeout=15) as response:
                    if response.status == 200:
                        content = response.read().decode('utf-8')
                        if '#EXTM3U' in content:
                            log(f"Stream check successful for {base_url}", xbmc.LOGDEBUG)
                            return refreshed_url
            except Exception as e:
                log(f"Stream refresh attempt {attempt + 1} failed: {str(e)}", xbmc.LOGDEBUG)
            time.sleep(3)
        return base_url
    
    def check_stream_health(self, url):
        try:
            # For a1xs.vip and jmp2.uk, use their own domain as referer
            if 'a1xs.vip' in url:
                referer = 'https://a1xs.vip/'
                origin = 'https://a1xs.vip'
            elif 'jmp2.uk' in url:
                referer = 'https://jmp2.uk/'
                origin = 'https://jmp2.uk'
            else:
                referer = 'https://google.com/'
                origin = 'https://google.com'
            
            headers = {
                'User-Agent': self.get_rotated_user_agent(),
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Cache-Control': 'no-cache',
                'Referer': referer,
                'Origin': origin
            }
            
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as response:
                content = response.read().decode('utf-8')
                is_valid = '#EXTM3U' in content
                if not is_valid:
                    log(f"Invalid M3U8 content from {url[:50]}...", xbmc.LOGDEBUG)
                    log(f"Response preview: {content[:200]}", xbmc.LOGDEBUG)
                return is_valid
        except Exception as e:
            log(f"Stream health check failed: {str(e)}", xbmc.LOGDEBUG)
            return False
    
    def create_robust_headers(self, url):
        if 'a1xs.vip' in url:
            referer = 'https://a1xs.vip/'
            origin = 'https://a1xs.vip'
        elif 'jmp2.uk' in url:
            referer = 'https://jmp2.uk/'
            origin = 'https://jmp2.uk'
        else:
            referer = 'https://google.com/'
            origin = 'https://google.com'
            
        headers = {
            'User-Agent': self.get_rotated_user_agent(),
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'identity',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Pragma': 'no-cache',
            'Referer': referer,
            'Origin': origin,
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin'
        }
        return '&'.join([f'{k}={urllib.parse.quote(v)}' for k, v in headers.items()])
    
    def play_robust_m3u8(self, url, list_item):
        list_item.setMimeType('application/vnd.apple.mpegurl')
        list_item.setContentLookup(False)
        list_item.setProperty('IsPlayable', 'true')
        self.setup_robust_inputstream(list_item, url)
        
        # Set headers for specific domains
        header_string = self.create_robust_headers(url)
        list_item.setProperty('inputstream.adaptive.stream_headers', header_string)
        list_item.setProperty('http-headers', header_string)
        
        # Additional properties for better playback
        list_item.setProperty('inputstream.adaptive.play_timeshift_buffer', 'true')
        list_item.setProperty('inputstream.adaptive.manifest_ttl', '3600')
        list_item.setProperty('inputstream.adaptive.segcount_playback', 'true')
        list_item.setProperty('inputstream.adaptive.allow_video_switching', 'false')
        
        log(f"Playing M3U8 URL: {url[:100]}...", xbmc.LOGINFO)
        list_item.setPath(url)
        xbmcplugin.setResolvedUrl(HANDLE, True, list_item)
        return True
    
    def monitor_playback(self):
        player = xbmc.Player()
        monitor = xbmc.Monitor()
        last_check = time.time()
        while not monitor.abortRequested() and player.isPlaying():
            if time.time() - last_check > 30:
                try:
                    playing_file = player.getPlayingFile()
                    if playing_file and ('.m3u8' in playing_file or 'a1xs.vip' in playing_file or 'jmp2.uk' in playing_file):
                        if not self.check_stream_health(playing_file):
                            log("Stream health check failed during playback", xbmc.LOGWARNING)
                            return False
                    last_check = time.time()
                except: pass
            if monitor.waitForAbort(5): break
        return True
    
    def test_m3u8_url(self, url):
        """Test if the M3U8 URL is accessible and valid"""
        try:
            if 'a1xs.vip' in url:
                referer = 'https://a1xs.vip/'
                origin = 'https://a1xs.vip'
            elif 'jmp2.uk' in url:
                referer = 'https://jmp2.uk/'
                origin = 'https://jmp2.uk'
            else:
                referer = 'https://google.com/'
                origin = 'https://google.com'
            
            headers = {
                'User-Agent': self.get_rotated_user_agent(),
                'Accept': '*/*',
                'Referer': referer,
                'Origin': origin
            }
            
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    content = response.read().decode('utf-8', errors='ignore')
                    return '#EXTM3U' in content
            return False
        except Exception as e:
            log(f"M3U8 test failed: {str(e)}", xbmc.LOGDEBUG)
            return False
    
    def play_video_with_recovery(self, link):
        if not self.security_manager.is_security_valid():
            return
        original_url = decrypt(link, ADDON_ID)
        if not original_url:
            log("Failed to decrypt URL", xbmc.LOGERROR)
            return
        
        log(f"Attempting to play: {original_url}", xbmc.LOGINFO)
        
        # Check if it's a problematic domain
        if 'a1xs.vip' in original_url or 'jmp2.uk' in original_url:
            log(f"Playing from enhanced domain: {original_url[:100]}...", xbmc.LOGINFO)
            
            # Test the URL first
            if not self.test_m3u8_url(original_url):
                log(f"URL test failed: {original_url}", xbmc.LOGWARNING)
                # Try adding .m3u8 if not present
                if not original_url.endswith('.m3u8') and not '.m3u8?' in original_url:
                    test_url = f"{original_url}.m3u8"
                    if self.test_m3u8_url(test_url):
                        original_url = test_url
                        log(f"Added .m3u8 extension, new URL: {original_url}", xbmc.LOGINFO)
        
        for attempt in range(3):  # Increased retries for robustness
            try:
                list_item = xbmcgui.ListItem()
                current_url = original_url
                
                # For specific domains, try to refresh the URL
                if attempt > 0 and ('jmp2.uk' in original_url or 'a1xs.vip' in original_url):
                    current_url = self.get_refreshed_stream(original_url)
                
                # Check if it looks like an M3U8 URL
                if '.m3u8' in current_url or current_url.endswith('.m3u8') or 'a1xs.vip' in current_url or 'jmp2.uk' in current_url:
                    log(f"Attempt {attempt + 1}: Playing as M3U8: {current_url[:100]}...", xbmc.LOGDEBUG)
                    if self.play_robust_m3u8(current_url, list_item):
                        if self.monitor_playback():
                            log("Playback successful", xbmc.LOGINFO)
                            return True
                else:
                    # Try resolveurl for non-m3u8 URLs
                    try:
                        log(f"Attempting resolveurl for: {current_url[:100]}...", xbmc.LOGDEBUG)
                        resolved_url = resolveurl.resolve(current_url)
                        if resolved_url:
                            list_item.setPath(resolved_url)
                            log(f"Resolved URL: {resolved_url[:100]}...", xbmc.LOGDEBUG)
                        else:
                            list_item.setPath(current_url)
                    except Exception as e:
                        log(f"resolveurl failed: {str(e)}", xbmc.LOGDEBUG)
                        list_item.setPath(current_url)
                    
                    list_item.setContentLookup(False)
                    xbmcplugin.setResolvedUrl(HANDLE, True, list_item)
                    log("Playback started (non-M3U8)", xbmc.LOGINFO)
                    return True
            except Exception as e:
                log(f"Playback attempt {attempt + 1} failed: {str(e)}", xbmc.LOGDEBUG)
            time.sleep(5)
        
        log(f"All playback attempts failed for: {original_url[:100]}...", xbmc.LOGERROR)
        xbmcgui.Dialog().notification('Playback Error', 'Could not establish stable stream connection', xbmcgui.NOTIFICATION_ERROR, 3000)
        xbmcplugin.setResolvedUrl(HANDLE, False, xbmcgui.ListItem())
    
    def play_video(self, link):
        if not self.security_manager.is_security_valid() or not self.security_manager.is_playback_allowed():
            if not self.security_manager.is_playback_allowed():
                self.security_manager.show_repository_required_message()
            xbmcplugin.setResolvedUrl(HANDLE, False, xbmcgui.ListItem())
            return
        self.play_video_with_recovery(link)
    
    def choose_and_play_stream(self, encrypted_json):
        if not self.security_manager.is_security_valid() or not self.security_manager.is_playback_allowed():
            if not self.security_manager.is_playback_allowed():
                self.security_manager.show_repository_required_message()
            return
        try:
            decrypted = decrypt(encrypted_json, PLUGIN_KEY)
            streams = json.loads(decrypted)
            if not streams:
                xbmcgui.Dialog().notification('No Streams', 'No streams available', xbmcgui.NOTIFICATION_ERROR, 2000)
                return
            
            stream_labels = []
            for stream in streams:
                label = stream.get('label', 'Unknown Stream')
                stream_labels.append(label)
            
            selected_idx = xbmcgui.Dialog().select('Select A Stream', stream_labels)
            if selected_idx >= 0:
                selected_stream = streams[selected_idx]
                self.play_video(encrypt(selected_stream['url'], ADDON_ID))
            else:
                xbmcgui.Dialog().notification('Selection Cancelled', 'No stream selected', xbmcgui.NOTIFICATION_INFO, 2000)
        except Exception as e:
            log(f"Stream selection error: {str(e)}", xbmc.LOGERROR)
            xbmcgui.Dialog().notification('Selection Error', 'Failed to choose a stream.', xbmcgui.NOTIFICATION_ERROR, 3000)

class MenuManager:
    def __init__(self):
        self.cache_manager = CacheManager()
        self.security_manager = SecurityManager()
        self.handle = HANDLE
    
    def load_local_json(self):
        try:
            if not xbmcvfs.exists(LOCAL_JSON_PATH):
                return []
            with xbmcvfs.File(LOCAL_JSON_PATH, 'r') as f:
                encrypted_content = f.read()
            if not encrypted_content:
                return []
            decrypted_content = decrypt(encrypted_content, OBFUSCATED_JSON_KEY)
            if decrypted_content:
                return json.loads(decrypted_content)
            else:
                return json.loads(encrypted_content)
        except:
            return []
    
    def get_main_menu_data(self):
        menu_data = self.load_local_json()
        clear_cache_item = {'title': '[COLOR lime]Clear Cache[/COLOR]','summary': 'Clear all temporary cache files','thumbnail': ADDON_ICON,'fanart': ADDON_FANART,'type': 'clear_cache'}
        if menu_data: menu_data.append(clear_cache_item)
        else: menu_data = [clear_cache_item]
        return menu_data
    
    def fetch_json(self, url):
        cached_data = self.cache_manager.get_cached_sublist(url)
        if cached_data is not None: return cached_data
        try:
            req = urllib.request.Request(url, headers={'User-Agent': f'{ADDON_NAME}/{ADDON_VERSION} (Kodi)','Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())
            self.cache_manager.cache_sublist(url, data)
            return data
        except Exception as e:
            log(f"Error fetching JSON from {url}: {str(e)}", xbmc.LOGERROR)
            return []
    
    def call_external_addon(self, addon_id, path, parameters=None):
        try:
            base_url = f"plugin://{addon_id}/{path}"
            if parameters:
                param_string = "&".join([f"{k}={v}" for k, v in parameters.items()])
                full_url = f"{base_url}?{param_string}"
            else:
                full_url = base_url
            xbmc.executebuiltin(f'Container.Update({full_url})')
            return True
        except Exception as e:
            log(f"Error calling external addon: {str(e)}", xbmc.LOGERROR)
            return False
    
    def list_items(self, json_url=None, is_main_list=False):
        if not self.security_manager.is_security_valid() or not self.security_manager.verify_repository_installed():
            if not self.security_manager.verify_repository_installed():
                self.security_manager.show_repository_required_message()
            xbmcplugin.endOfDirectory(self.handle)
            return
            
        items = self.get_main_menu_data() if is_main_list else self.fetch_json(decrypt(json_url, PLUGIN_KEY))
        if not items:
            xbmcgui.Dialog().notification('No Content', 'No content available at this time.', xbmcgui.NOTIFICATION_INFO, 2000)
            xbmcplugin.endOfDirectory(self.handle)
            return
            
        for item in items:
            title = item.get('title', 'Untitled')
            summary = item.get('summary', 'No description available.')
            thumbnail = item.get('thumbnail', ADDON_ICON)
            fanart = item.get('fanart', ADDON_FANART)
            list_item = xbmcgui.ListItem(label=title)
            list_item.setArt({'thumb': thumbnail, 'icon': thumbnail, 'fanart': fanart})
            list_item.setInfo('video', {'title': title, 'plot': summary, 'genre': item.get('genre', ''), 'year': item.get('year', ''), 'rating': item.get('rating', '')})
            
            if item.get('type') == 'clear_cache':
                url = get_url(action='clear_cache')
                list_item.setProperty('IsPlayable', 'false')
                xbmcplugin.addDirectoryItem(self.handle, url, list_item, isFolder=False)
            elif item.get('type') == 'external_addon':
                addon_id = item.get('addon_id')
                addon_path = item.get('addon_path')
                addon_params = item.get('addon_params', {})
                base_url = f"plugin://{addon_id}/{addon_path}"
                if addon_params:
                    param_string = "&".join([f"{k}={v}" for k, v in addon_params.items()])
                    external_url = f"{base_url}?{param_string}"
                else:
                    external_url = base_url
                xbmcplugin.addDirectoryItem(self.handle, external_url, list_item, isFolder=True)
            elif item.get('is_dir', False):
                url = get_url(action='list', url=encrypt(item['link'], PLUGIN_KEY))
                xbmcplugin.addDirectoryItem(self.handle, url, list_item, isFolder=True)
            elif item.get('link') == 'magnet:':
                url = get_url(action='no_link')
                xbmcplugin.addDirectoryItem(self.handle, url, list_item, isFolder=False)
            elif 'links' in item and isinstance(item['links'], list):
                encoded_links = encrypt(json.dumps(item['links']), PLUGIN_KEY)
                url = get_url(action='choose_stream', urls=encoded_links)
                list_item.setProperty('IsPlayable', 'true')
                xbmcplugin.addDirectoryItem(self.handle, url, list_item, isFolder=False)
            elif 'link' in item:
                url = get_url(action='play', url=encrypt(item['link'], ADDON_ID))
                list_item.setProperty('IsPlayable', 'true')
                xbmcplugin.addDirectoryItem(self.handle, url, list_item, isFolder=False)
                
        xbmcplugin.endOfDirectory(self.handle)

class Router:
    def __init__(self):
        self.security_manager = SecurityManager()
        self.menu_manager = MenuManager()
        self.playback_manager = PlaybackManager()
        self.cache_manager = CacheManager()
        self.handle = HANDLE
    
    def route(self, params):
        if not self.security_manager.is_security_valid():
            xbmcplugin.endOfDirectory(self.handle)
            return
            
        if not isinstance(params, dict): params = {}
        
        try:
            action = params.get('action', '')
            url = params.get('url', '')
            urls = params.get('urls', '')
            
            if action == 'list' and url:
                self.menu_manager.list_items(url, is_main_list=False)
            elif action == 'play' and url:
                self.playback_manager.play_video(url)
            elif action == 'choose_stream' and urls:
                self.playback_manager.choose_and_play_stream(urls)
            elif action == 'clear_cache':
                self.cache_manager.clear_cache_safe()
                xbmcplugin.endOfDirectory(self.handle, succeeded=False)
            elif action == 'no_link':
                xbmcgui.Dialog().notification('No Stream', 'This item is not playable.', xbmcgui.NOTIFICATION_INFO, 2000)
            else:
                if not self.security_manager.verify_repository_installed():
                    self.security_manager.show_repository_required_message()
                    xbmcplugin.endOfDirectory(self.handle)
                    return
                self.menu_manager.list_items(is_main_list=True)
        except Exception as e:
            log(f"Router error: {str(e)}", xbmc.LOGERROR)
            xbmcgui.Dialog().notification('Error', 'Failed to process request', xbmcgui.NOTIFICATION_ERROR, 3000)
            xbmcplugin.endOfDirectory(self.handle)

def main():
    try:
        params = {}
        if len(sys.argv) > 2 and sys.argv[2]:
            params = dict(urllib.parse.parse_qsl(sys.argv[2][1:]))
        router = Router()
        router.route(params)
    except Exception as e:
        xbmc.log(f"Fatal error in main: {str(e)}", xbmc.LOGERROR)
        xbmcplugin.endOfDirectory(int(sys.argv[1]))

if __name__ == '__main__':
    main()
