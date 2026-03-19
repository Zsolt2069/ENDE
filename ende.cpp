/*
Simple C++ GUI File Encryptor/Decryptor

Features:
- Pick input file to encrypt, pick output file, click "Encrypt".
- Pick encrypted file, output path, click "Decrypt".
- Shows "Successfully Encrypted" (or Decrypted) on completion.
- Decrypt only works for files made by this app (magic header).
- Uses simple XOR password (for demo, not for security).

Requires: g++, Windows, linked to comdlg32, gdi32, user32.

Compile: g++ -mwindows encryptor_gui.cpp -o encryptor_gui.exe

*/

#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <string>
#define MAGIC_HEADER "ENCR1"
#define MAGIC_LEN 5

// Util: file open/save dialog
int get_file_path(HWND hwnd, char* filename, DWORD save) {
    OPENFILENAMEA ofn = {0};
    filename[0] = '\0';
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = "All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST;
    if (save)
        ofn.Flags |= OFN_OVERWRITEPROMPT;
    return save ? GetSaveFileNameA(&ofn) : GetOpenFileNameA(&ofn);
}

// XOR encrypt/decrypt. Only for demo, not real security.
void xor_crypt(const char* in, const char* out, const char* pass, int encrypt) {
    FILE* fin = fopen(in, "rb");
    FILE* fout = fopen(out, "wb");
    if (!fin || !fout) { if (fin) fclose(fin); if (fout) fclose(fout); return; }
    if (encrypt) {
        fwrite(MAGIC_HEADER, 1, MAGIC_LEN, fout);
    } else {
        char magic[MAGIC_LEN+1] = {0};
        fread(magic, 1, MAGIC_LEN, fin);
        if (strncmp(magic, MAGIC_HEADER, MAGIC_LEN) != 0) {
            fclose(fin); fclose(fout); remove(out);
            return;
        }
    }
    int c, i = 0, passlen = (int)strlen(pass);
    while ((c = fgetc(fin)) != EOF) {
        if (!encrypt && ftell(fin) <= MAGIC_LEN) continue; // skip magic read
        unsigned char b = (unsigned char)c;
        unsigned char e = b ^ (unsigned char)pass[i % passlen];
        fputc(e, fout);
        ++i;
    }
    fclose(fin); fclose(fout);
}

// GUI globals
char input_file[MAX_PATH] = "";
char output_file[MAX_PATH] = "";
char password[64] = "secret"; // Default password

// Controls
static HWND hInput, hOutput, hPass, hEncrypt, hDecrypt;

// GUI helpers
void set_input(HWND hwnd) {
    if (get_file_path(hwnd, input_file, 0))
        SetWindowTextA(hInput, input_file);
}
void set_output(HWND hwnd) {
    if (get_file_path(hwnd, output_file, 1))
        SetWindowTextA(hOutput, output_file);
}

// Encrypt Button click
void do_encrypt(HWND hwnd) {
    GetWindowTextA(hInput, input_file, MAX_PATH);
    GetWindowTextA(hOutput, output_file, MAX_PATH);
    GetWindowTextA(hPass, password, 63);
    password[63] = 0;
    if (input_file[0] == 0 || output_file[0] == 0 || password[0] == 0) {
        MessageBoxA(hwnd, "Select input/output and enter a password.", "Missing", MB_OK|MB_ICONWARNING);
        return;
    }
    xor_crypt(input_file, output_file, password, 1);
    MessageBoxA(hwnd, "Your file is Successfully encrypted!", "Success", MB_OK|MB_ICONINFORMATION);
}

// Decrypt Button click
void do_decrypt(HWND hwnd) {
    if (get_file_path(hwnd, input_file, 0)) SetWindowTextA(hInput, input_file);
    if (get_file_path(hwnd, output_file, 1)) SetWindowTextA(hOutput, output_file);
    GetWindowTextA(hPass, password, 63);
    password[63]=0;
    if (input_file[0] == 0 || output_file[0] == 0 || password[0] == 0) {
        MessageBoxA(hwnd, "Select files & enter a password.", "Missing", MB_OK|MB_ICONWARNING);
        return;
    }
    FILE* check = fopen(input_file, "rb");
    if (!check) return;
    char magic[MAGIC_LEN+1] = {0};
    fread(magic, 1, MAGIC_LEN, check);
    fclose(check);
    if (strncmp(magic, MAGIC_HEADER, MAGIC_LEN) != 0) {
        MessageBoxA(hwnd, "Selected file was not encrypted by this app!", "Invalid File", MB_OK|MB_ICONERROR);
        return;
    }
    xor_crypt(input_file, output_file, password, 0);
    MessageBoxA(hwnd, "Decryption complete!", "Success", MB_OK|MB_ICONINFORMATION);
}

// Window Procedure
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        CreateWindowA("STATIC", "Simple File Encryptor/Decryptor", WS_VISIBLE|WS_CHILD, 10,10,220,24, hwnd,0,0,0);
        hInput = CreateWindowA("EDIT","",WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL, 10,40,260,24, hwnd,0,0,0);
        CreateWindowA("BUTTON","Select Input...",WS_VISIBLE|WS_CHILD,280,40,130,24,hwnd,(HMENU)1,0,0);
        hOutput = CreateWindowA("EDIT","",WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL,10,70,260,24,hwnd,0,0,0);
        CreateWindowA("BUTTON","Select Output...",WS_VISIBLE|WS_CHILD,280,70,130,24,hwnd,(HMENU)2,0,0);
        CreateWindowA("STATIC","Password:",WS_VISIBLE|WS_CHILD,10,105,80,24,hwnd,0,0,0);
        hPass = CreateWindowA("EDIT","secret",WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL,90,105,170,24,hwnd,0,0,0);
        hEncrypt = CreateWindowA("BUTTON", "Encrypt!", WS_VISIBLE|WS_CHILD, 10,140,180,36,hwnd,(HMENU)3,0,0);
        hDecrypt = CreateWindowA("BUTTON", "Decrypt!", WS_VISIBLE|WS_CHILD, 210,140,200,36,hwnd,(HMENU)4,0,0);
        break;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
            case 1: set_input(hwnd); break;
            case 2: set_output(hwnd); break;
            case 3: do_encrypt(hwnd); break;
            case 4: do_decrypt(hwnd); break;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

// Main
int WINAPI WinMain(HINSTANCE hInst,HINSTANCE,LPSTR,int){
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = "EncryptorApp";
    wc.hCursor = LoadCursorA(0, IDC_ARROW);
    RegisterClassA(&wc);
    HWND hwnd = CreateWindowA("EncryptorApp","Simple File Encryptor/Decryptor",WS_OVERLAPPEDWINDOW&~WS_THICKFRAME,250,250,440,240,0,0,hInst,0);
    ShowWindow(hwnd, SW_SHOWNORMAL);
    MSG msg;
    while (GetMessageA(&msg,0,0,0)>0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return 0;
}