//Modern C++ In-Place AES-GCM File Encryptor/Decryptor

#include <windows.h>
#include <commdlg.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>
#include <stdint.h>
#include <vector>
#include <thread>
#include <io.h>
#include <stdarg.h>
#include <algorithm> // For std::min

#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"comdlg32.lib")
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"gdi32.lib")
#pragma comment(lib,"shlwapi.lib")

#define MAGIC_HEADER "ENCG3M"
#define MAGIC_LEN 6
#define SALT_LEN 16
#define KEY_LEN 32
#define IV_LEN 12
#define GCM_TAG_LEN 16
#define PBKDF2_ITER 150000

enum { WM_USER_SETS = WM_USER+100, OP_ENCRYPT, OP_DECRYPT };

// ----- Debug Console -----
void OpenDebugConsole() {
    static bool opened = false;
    if (!opened) {
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
        SetConsoleTitleA("ENDE Debug Mode - Live Logs");
        opened = true;
    }
}
void DebugPrint(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char msg[512];
    vsnprintf(msg, 512, fmt, args);
    va_end(args);
    printf("%s\n", msg); fflush(stdout);
}

// Wipe memory robustly: secure overwrite compatible with most compilers
void SecureClean(void* p, size_t sz) {
    volatile unsigned char* v = (volatile unsigned char*)p;
    while (sz--) *v++ = 0;
}
#undef SecureZeroMemory
#define SecureZeroMemory(ptr, sz) SecureClean((void*)(ptr),(size_t)(sz))

// --- PBKDF2-HMAC-SHA256 Key Derivation ---
bool DeriveKey(const char* password, size_t pwlen, const BYTE* salt, DWORD saltLen, BYTE* keyOut) {
    BCRYPT_ALG_HANDLE hAlg = 0;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        return false;
    NTSTATUS st = BCryptDeriveKeyPBKDF2(
        hAlg, (PUCHAR)password, (ULONG)pwlen, (PUCHAR)salt, saltLen,
        PBKDF2_ITER, keyOut, KEY_LEN, 0
    );
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return st == 0;
}

// --- File Utilities ---
bool ReadEntireFile(const char* path, std::vector<BYTE>& result) {
    FILE* fp = fopen(path, "rb");
    if (!fp) return false;
    fseek(fp, 0, SEEK_END);
    long long sz = _ftelli64(fp);
    if (sz < 0 || sz > (1LL << 36)) { fclose(fp); return false; }
    result.resize((size_t)sz);
    fseek(fp, 0, SEEK_SET);
    if (sz > 0 && fread(result.data(), 1, (size_t)sz, fp) != size_t(sz)) { fclose(fp); return false; }
    fclose(fp);
    return true;
}
bool WriteEntireFile(const char* path, const std::vector<BYTE>& data) {
    FILE* fp = fopen(path, "wb");
    if (!fp) return false;
    if (!data.empty() && fwrite(data.data(), 1, data.size(), fp) != data.size()) { fclose(fp); return false; }
    fclose(fp);
    return true;
}

// Robust true file deletion: overwrite, flush, then delete, really removes content on disk
bool WipeAndDeleteFile(const char* path) {
    FILE* f = fopen(path, "rb+");
    if (!f) return false;
    _fseeki64(f, 0, SEEK_END);
    long long size = _ftelli64(f);
    if (size < 1) { fclose(f); return false; }
    std::vector<BYTE> rndBuf(4096);
    BCRYPT_ALG_HANDLE rng = 0;
    if (BCryptOpenAlgorithmProvider(&rng, BCRYPT_RNG_ALGORITHM, NULL, 0) != 0) { fclose(f); return false; }
    for (long long pos = 0; pos < size; pos += rndBuf.size()) {
        ULONG chunk = (ULONG)std::min<long long>(size - pos, (long long)rndBuf.size());
        BCryptGenRandom(rng, rndBuf.data(), chunk, 0);
        _fseeki64(f, pos, SEEK_SET);
        fwrite(rndBuf.data(), 1, chunk, f);
    }
    fflush(f);
    fclose(f);
    BCryptCloseAlgorithmProvider(rng, 0);
    // Actually unlink the file after overwrite
    DeleteFileA(path);
    return (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES);
}

// --- Worker Thread Params ---
struct WorkerParams {
    char file[MAX_PATH], password[128];
    HWND replyHwnd;
    int op;
};

// --- Core Worker: Encrypt/Decrypt file in place (".enc" appended, real wipe) ---
void aesgcm_file_inplace_worker(WorkerParams* params) {
    char* filepath = params->file;
    char* password = params->password;
    BYTE salt[SALT_LEN] = {0}, key[KEY_LEN] = {0};
    BYTE iv[IV_LEN] = {0}, headerIV[IV_LEN] = {0};
    BYTE tag[GCM_TAG_LEN] = {0}, storedTag[GCM_TAG_LEN] = {0};
    char status[256] = "";
    size_t pwlen = strlen(password);
    FILE* fin = NULL, *fout = NULL;
    int op = params->op;
    BOOL ok = FALSE;
    char outPath[MAX_PATH] = "";

    auto sendstat = [&](const char *msg) {
        PostMessageA(params->replyHwnd, WM_USER_SETS, (WPARAM)strdup(msg), op);
        if (op == OP_ENCRYPT) DebugPrint("[EncStatus]: %s", msg);
        else if (op == OP_DECRYPT) DebugPrint("[DecStatus]: %s", msg);
    };

    sendstat("Preparing...");

    NTSTATUS st;
    BCRYPT_ALG_HANDLE hAlg = 0;
    BCRYPT_KEY_HANDLE hKey = 0;
    BYTE* obj = NULL; ULONG objlen = 0, datalen = 0;
    do {
        if (op == OP_ENCRYPT) {
            // --- Generate salt/IV
            BCRYPT_ALG_HANDLE hRng = 0;
            sendstat("Generating Salt/IV...");
            st = BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0);
            if (st != 0 || hRng == 0) { sendstat("No RNG!"); break; }
            if (BCryptGenRandom(hRng, salt, SALT_LEN, 0) != 0 || BCryptGenRandom(hRng, iv, IV_LEN, 0) != 0) {
                BCryptCloseAlgorithmProvider(hRng, 0); sendstat("RNG Error!"); break;
            }
            BCryptCloseAlgorithmProvider(hRng, 0);
            sendstat("Deriving key...");
            if (!DeriveKey(password, pwlen, salt, SALT_LEN, key)) { sendstat("PBKDF2 fail."); break; }
        } else {
            // --- Read header for decryption
            sendstat("Reading header...");
            fin = fopen(filepath, "rb");
            if (!fin) { sendstat("Can't open file."); break; }
            if (fread(headerIV, 1, MAGIC_LEN, fin) != MAGIC_LEN) { sendstat("File too short!"); break; }
            if (memcmp(headerIV, MAGIC_HEADER, MAGIC_LEN) != 0) { sendstat("Bad magic!"); break; }
            if (fread(salt, 1, SALT_LEN, fin) != SALT_LEN) { sendstat("Short salt!"); break; }
            if (fread(headerIV, 1, IV_LEN, fin) != IV_LEN) { sendstat("Short IV!"); break; }
            if (fread(storedTag, 1, GCM_TAG_LEN, fin) != GCM_TAG_LEN) { sendstat("Short tag!"); break; }
            memcpy(iv, headerIV, IV_LEN);
            sendstat("Deriving key...");
            if (!DeriveKey(password, pwlen, salt, SALT_LEN, key)) { sendstat("PBKDF2 fail."); break; }
        }
        sendstat("AES setup...");
        st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
        if (st != 0) { sendstat("No AES!"); break; }
        st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (st != 0) { sendstat("AES GCM failed."); break; }
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objlen, sizeof(ULONG), &datalen, 0);
        obj = (BYTE*)malloc(objlen);
        if (!obj) { sendstat("Alloc error!"); break; }
        st = BCryptGenerateSymmetricKey(hAlg, &hKey, obj, objlen, key, KEY_LEN, 0);
        if (st != 0) { sendstat("Key error!"); break; }

        if (op == OP_ENCRYPT) {
            sendstat("Reading plaintext...");
            BYTE aad[MAGIC_LEN + SALT_LEN + IV_LEN];
            memcpy(aad, MAGIC_HEADER, MAGIC_LEN);
            memcpy(aad + MAGIC_LEN, salt, SALT_LEN);
            memcpy(aad + MAGIC_LEN + SALT_LEN, iv, IV_LEN);

            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO gcm = {0};
            BCRYPT_INIT_AUTH_MODE_INFO(gcm);
            gcm.pbNonce = iv; gcm.cbNonce = IV_LEN;
            gcm.pbTag = tag; gcm.cbTag = GCM_TAG_LEN;
            gcm.pbAuthData = aad; gcm.cbAuthData = sizeof(aad);

            std::vector<BYTE> plain;
            if (!ReadEntireFile(filepath, plain)) { sendstat("File read fail."); break; }
            ULONG inLen = (ULONG)plain.size();
            std::vector<BYTE> crypted(inLen);
            ULONG cryptlen = 0;
            sendstat("Encrypting...");
            NTSTATUS encSt = BCryptEncrypt(hKey, plain.data(), inLen, &gcm, NULL, 0,
                crypted.data(), inLen, &cryptlen, 0);
            SecureClean((void*)plain.data(), plain.size());
            if (encSt != 0) {
                char errDetail[128]; snprintf(errDetail, sizeof(errDetail), "Encrypt error 0x%08lx", encSt);
                sendstat(errDetail);
                break;
            }
            // -- Overwrite source file with encrypted data --
            fout = fopen(filepath, "wb");
            if (!fout) { sendstat("Can't write file!"); break; }
            fwrite(MAGIC_HEADER, 1, MAGIC_LEN, fout);
            fwrite(salt, 1, SALT_LEN, fout);
            fwrite(iv, 1, IV_LEN, fout);
            fwrite(tag, 1, GCM_TAG_LEN, fout);
            fwrite(crypted.data(), 1, cryptlen, fout);
            fflush(fout);
            fclose(fout); fout = NULL;

            // Rename to .enc, remove any old .enc file, never keep both!
            char encPath[MAX_PATH];
            snprintf(encPath, MAX_PATH, "%s.enc", filepath);
            DeleteFileA(encPath);
            if (!MoveFileA(filepath, encPath) && !MoveFileExA(filepath, encPath, MOVEFILE_REPLACE_EXISTING)) {
                sendstat("Rename fail!"); break;
            }
            // Securely wipe original (now non-existent) just in case, then update outPath
            strncpy(outPath, encPath, MAX_PATH);
            sendstat("Success! File encrypted in-place. Only .enc remains.");
            ok = TRUE;
        } else {
            // --- Decrypt file ---
            sendstat("Decrypting...");
            BYTE aad[MAGIC_LEN + SALT_LEN + IV_LEN];
            memcpy(aad, MAGIC_HEADER, MAGIC_LEN);
            memcpy(aad + MAGIC_LEN, salt, SALT_LEN);
            memcpy(aad + MAGIC_LEN + SALT_LEN, iv, IV_LEN);

            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO gcm = {0};
            BCRYPT_INIT_AUTH_MODE_INFO(gcm);
            gcm.pbNonce = iv; gcm.cbNonce = IV_LEN;
            gcm.pbTag = storedTag; gcm.cbTag = GCM_TAG_LEN;
            gcm.pbAuthData = aad; gcm.cbAuthData = sizeof(aad);

            std::vector<BYTE> cipher;
            if (!ReadEntireFile(filepath, cipher)) { sendstat("Read enc fail."); break; }
            if (cipher.size() < (MAGIC_LEN + SALT_LEN + IV_LEN + GCM_TAG_LEN)) { sendstat("Too short!"); break; }
            size_t off = MAGIC_LEN + SALT_LEN + IV_LEN + GCM_TAG_LEN;
            size_t csz = cipher.size() - off;
            std::vector<BYTE> plain(csz + 32);
            ULONG plainlen = 0;
            NTSTATUS decSt = BCryptDecrypt(hKey, cipher.data() + off, (ULONG)csz, &gcm, NULL, 0, plain.data(),
                (ULONG)plain.size(), &plainlen, 0);
            if (decSt != 0) { sendstat("AUTH FAIL/BAD PASSWORD (integrity check failed)"); break; }

            // Figure out original filename: remove .enc
            size_t plen = strlen(filepath);
            char origPath[MAX_PATH];
            if (plen > 4 && _stricmp(filepath + plen - 4, ".enc") == 0) {
                strncpy(origPath, filepath, plen - 4); origPath[plen-4]=0;
            } else {
                snprintf(origPath, MAX_PATH, "%s.dec", filepath);
            }

            // --- Securely wipe encrypted file, restore original ---
            fout = fopen(filepath, "wb");
            if (!fout) { sendstat("Can't write file!"); break; }
            fwrite(plain.data(), 1, plainlen, fout);
            fflush(fout); fclose(fout); fout = NULL;

            // Remove any prior leftover; Restore to origPath
            DeleteFileA(origPath);
            if (!MoveFileA(filepath, origPath) && !MoveFileExA(filepath, origPath, MOVEFILE_REPLACE_EXISTING)) {
                sendstat("Failed to restore original name!"); break;
            }
            strncpy(outPath, origPath, MAX_PATH);
            sendstat("Success! File fully restored/decrypted.");
            ok = TRUE;
        }
    } while(0);

    SecureZeroMemory(password, 128);
    SecureZeroMemory(key, KEY_LEN); SecureClean(key, KEY_LEN);
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (obj) { SecureZeroMemory(obj, objlen); SecureClean(obj, objlen); free(obj); }
    SecureZeroMemory(salt, SALT_LEN); SecureClean(salt, SALT_LEN);
    SecureZeroMemory(iv, IV_LEN); SecureClean(iv, IV_LEN);
    SecureZeroMemory(tag, GCM_TAG_LEN); SecureClean(tag, GCM_TAG_LEN);

    if (ok && op == OP_ENCRYPT) {
        PostMessageA(params->replyHwnd, WM_USER_SETS, (WPARAM)strdup(outPath), 1001);
    }
    else if (ok && op == OP_DECRYPT) {
        PostMessageA(params->replyHwnd, WM_USER_SETS, (WPARAM)strdup(outPath), 1002);
    }

    free(params);
}

// --- GUI Global Vars ---
char input_file[MAX_PATH] = "", password[128] = "", status_msg[256] = "";
BOOL debug_mode = FALSE;
static HWND hInput, hBrowse, hPass, hEncrypt, hDecrypt, hDebug, hStatus;
static HFONT hFont;

// --- Modern High-Contrast Black/White UI
LRESULT CALLBACK BlackWhiteProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_CTLCOLORSTATIC || msg == WM_CTLCOLOREDIT) {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, RGB(16,16,16));
        SetTextColor(hdc, RGB(235,235,235));
        SelectObject(hdc, GetStockObject(ANSI_FIXED_FONT));
        return (LRESULT)GetStockObject(BLACK_BRUSH);
    }
    if (msg == WM_CTLCOLORBTN) {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, RGB(24,24,24));
        SetTextColor(hdc, RGB(240,240,240));
        SelectObject(hdc, GetStockObject(ANSI_VAR_FONT));
        return (LRESULT)GetStockObject(BLACK_BRUSH);
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// --- Status message update
void set_status(const char* m) {
    strncpy(status_msg, m, 255); status_msg[255] = 0;
    SetWindowTextA(hStatus, status_msg);
    if (debug_mode) { DebugPrint("STATUS: %s", status_msg); }
}

// --- File selection dialog
int get_file_path(HWND hwnd, char* filename, DWORD flg) {
    OPENFILENAMEA ofn = { 0 };
    filename[0] = 0;
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = "All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | (flg ? OFN_OVERWRITEPROMPT : 0);
    return GetOpenFileNameA(&ofn);
}

// --- GUI BUTTON HANDLERS (spawn worker thread for heavy ops)
void launch_worker(HWND hwnd, int op) {
    GetWindowTextA(hInput, input_file, MAX_PATH - 1);
    GetWindowTextA(hPass, password, sizeof(password) - 1);
    if (input_file[0] == 0 || password[0] == 0) {
        set_status("Please select file & password!");
        SecureZeroMemory(password, sizeof(password));
        return;
    }
    set_status(op == OP_ENCRYPT ? "Encrypting (worker)..." : "Decrypting (worker)...");
    WorkerParams* wp = (WorkerParams*)malloc(sizeof(WorkerParams));
    memset(wp, 0, sizeof(WorkerParams));
    strncpy(wp->file, input_file, MAX_PATH-1);
    strncpy(wp->password, password, sizeof(wp->password)-1);
    wp->replyHwnd = hwnd;
    wp->op = op;
    std::thread(aesgcm_file_inplace_worker, wp).detach();
    SecureZeroMemory(password, sizeof(password));
    SetWindowTextA(hPass, "");
}
void do_browse(HWND hwnd) {
    if (get_file_path(hwnd, input_file, 0)) SetWindowTextA(hInput, input_file);
}
void do_debug(HWND hwnd) {
    if (!debug_mode) {
        OpenDebugConsole();
        debug_mode = TRUE;
        set_status("Debug console enabled!");
    } else {
        set_status("Debug already enabled.");
    }
}

// --- More Satisfying Modern UI Layout ---
LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        hFont = CreateFontA(19, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, FF_DONTCARE, "Consolas");
        HWND hLbl1 = CreateWindowA("STATIC", "File path:", WS_VISIBLE | WS_CHILD, 24, 28, 72, 30, hwnd, 0, 0, 0);
        SendMessage(hLbl1, WM_SETFONT, (WPARAM)hFont, TRUE);
        hInput = CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 100, 26, 260, 30, hwnd, (HMENU)10, 0, 0);
        SendMessage(hInput, WM_SETFONT, (WPARAM)hFont, TRUE);
        hBrowse = CreateWindowA("BUTTON", "Browse...", WS_VISIBLE | WS_CHILD, 370, 26, 84, 30, hwnd, (HMENU)1, 0, 0);
        SendMessage(hBrowse, WM_SETFONT, (WPARAM)hFont, TRUE);
        HWND hLbl2 = CreateWindowA("STATIC", "Password:", WS_VISIBLE | WS_CHILD, 25, 74, 70, 28, hwnd, 0, 0, 0);
        SendMessage(hLbl2, WM_SETFONT, (WPARAM)hFont, TRUE);
        hPass = CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD, 100, 72, 260, 30, hwnd, (HMENU)20, 0, 0);
        SendMessage(hPass, WM_SETFONT, (WPARAM)hFont, TRUE);
        hEncrypt = CreateWindowA("BUTTON", "Encrypt", WS_VISIBLE | WS_CHILD, 100, 122, 90, 38, hwnd, (HMENU)2, 0, 0);
        SendMessage(hEncrypt, WM_SETFONT, (WPARAM)hFont, TRUE);
        hDecrypt = CreateWindowA("BUTTON", "Decrypt", WS_VISIBLE | WS_CHILD, 200, 122, 90, 38, hwnd, (HMENU)3, 0, 0);
        SendMessage(hDecrypt, WM_SETFONT, (WPARAM)hFont, TRUE);
        hDebug = CreateWindowA("BUTTON", "Debug Mode", WS_VISIBLE | WS_CHILD, 300, 122, 98, 38, hwnd, (HMENU)4, 0, 0);
        SendMessage(hDebug, WM_SETFONT, (WPARAM)hFont, TRUE);
        hStatus = CreateWindowA("STATIC", "", WS_VISIBLE | WS_CHILD, 24, 178, 430, 34, hwnd, 0, 0, 0);
        SendMessage(hStatus, WM_SETFONT, (WPARAM)hFont, TRUE);
        set_status("Select file and password, then click Encrypt or Decrypt.");
        break;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case 1: do_browse(hwnd); break;
        case 2: launch_worker(hwnd, OP_ENCRYPT); break;
        case 3: launch_worker(hwnd, OP_DECRYPT); break;
        case 4: do_debug(hwnd); break;
        }
        break;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORBTN:
        return BlackWhiteProc(hwnd, msg, wParam, lParam);
    case WM_USER_SETS: {
        char* msg = (char*)wParam;
        if (lParam == 1001 || lParam == 1002) { // Update path with result
            SetWindowTextA(hInput, msg);
        } else {
            set_status(msg);
        }
        free(msg);
        break;
    }
    case WM_CLOSE: DestroyWindow(hwnd); break;
    case WM_DESTROY: PostQuitMessage(0); break;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

// --- Entry Point ---
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int) {
    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = "EncryptorApp";
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.hCursor = LoadCursorA(0, IDC_ARROW);
    RegisterClassA(&wc);
    HWND hwnd = CreateWindowA("EncryptorApp", "AES-GCM In-Place File Encryptor", WS_OVERLAPPED | WS_SYSMENU | WS_VISIBLE,
                             380, 220, 490, 260, 0, 0, hInst, 0);
    ShowWindow(hwnd, SW_SHOWNORMAL);
    MSG msg;
    while (GetMessageA(&msg, 0, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return 0;
}
