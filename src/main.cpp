/**
 * PointerBulucu - KnightOnline Pointer Finder
 * KO PTR scanner ve offset bulucu
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d9.h>
#include <iostream>
#include <vector>
#include <string>
#include <tlhelp32.h>
#include <psapi.h>
#include <fstream>

#pragma warning(disable : 4244)

// ImGui headers - imgui klasorunden
#include "../imgui/imgui.h"
#include "../imgui/backends/imgui_impl_dx9.h"
#include "../imgui/backends/imgui_impl_win32.h"

// ImGui Win32 implementation forward declaration
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);


// Global variables
HWND g_hWnd = nullptr;
IDirect3D9* g_pD3D = nullptr;
IDirect3DDevice9* g_pd3dDevice = nullptr;
D3DPRESENT_PARAMETERS g_d3dpp = {};

// Process ve Memory değişkenleri
HANDLE g_hProcess = nullptr;
DWORD g_processId = 0;
bool g_attached = false;

// KnightOnline Pointerları
struct KOPointers {
    DWORD_PTR KO_PTR_CHR;  // Character pointer
    DWORD_PTR KO_PTR_PKT;  // Packet pointer
    DWORD_PTR KO_PTR_DLG;  // Dialog pointer
    DWORD_PTR KO_SND_FNC;  // Send function
    DWORD_PTR KO_RCV_FNC;  // Receive function
    DWORD_PTR KO_FLDB;     // Function list base
    DWORD_PTR KO_FMBS;     // Function multi base
} g_KO_PTR = {0};

// Pointer scan sonuçları
struct FoundPointer {
    std::string name;
    DWORD_PTR address;
    std::vector<DWORD_PTR> offsets;
    int value;
};
std::vector<FoundPointer> g_foundPointers;

// Arama durumları
bool g_scanning = false;
bool g_autoScanning = false;
char g_searchPattern[256] = "";
int g_searchValue = 0;

// Module base adresi
DWORD_PTR g_moduleBase = 0;
DWORD g_moduleSize = 0;

// KO için bilinen mutlak adresler (KO.exe için)
// Bu adresler direkt kullanılır (module base eklenmez)
#define KO_ADDR_CHR 0x01092964  // Character pointer (mutlak adres)
#define KO_ADDR_DLG 0x01092A14  // Dialog pointer (mutlak adres)
#define KO_ADDR_PKT 0x010929BC  // Packet pointer (yaklaşık)

// Forward declarations
bool InitD3D(HWND hWnd);
void CleanupD3D();
void RenderFrame();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
bool AttachToKO();
void DetachFromProcess();
bool ReadMemory(DWORD_PTR address, void* buffer, size_t size);
void RenderMainWindow();
void ScanKOPointers();
void SavePointersToFile();
void LoadPointersFromFile();
DWORD_PTR FindModuleBase(const char* moduleName);
bool PatternScan(const BYTE* pattern, const char* mask, DWORD_PTR& outAddress);
DWORD_PTR ScanForPointer(DWORD_PTR targetAddress, DWORD_PTR startAddr, DWORD size);

/**
 * Ana giriş noktası
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Window class oluştur
    WNDCLASSEXW wc = { 0 };
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = L"PointerBulucuClass";

    RegisterClassExW(&wc);

    // Pencere oluştur
    g_hWnd = CreateWindowExW(
        0,
        L"PointerBulucuClass",
        L"KO PointerBulucu - KnightOnline PTR Scanner",
        WS_OVERLAPPEDWINDOW,
        100, 100, 1000, 700,
        nullptr, nullptr, wc.hInstance, nullptr
    );

    if (!g_hWnd) {
        return -1;
    }

    // Direct3D başlat
    if (!InitD3D(g_hWnd)) {
        CleanupD3D();
        UnregisterClassW(L"PointerBulucuClass", wc.hInstance);
        return -1;
    }

    // ImGui başlat
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;

    ImGui::StyleColorsDark();

    ImGui_ImplWin32_Init(g_hWnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);

    // KnightOnline'ye otomatik bağlan
    AttachToKO();

    // Pencereyi göster
    ShowWindow(g_hWnd, SW_SHOWDEFAULT);
    UpdateWindow(g_hWnd);

    // Ana mesaj döngüsü - render ile
    MSG msg;
    bool done = false;
    while (!done) {
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                done = true;
            } else {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
        if (done) break;
        
        // Render frame
        RenderFrame();
    }

    // Temizle
    DetachFromProcess();
    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupD3D();
    DestroyWindow(g_hWnd);
    UnregisterClassW(L"PointerBulucuClass", wc.hInstance);

    return 0;
}

/**
 * Direct3D başlatma
 */
bool InitD3D(HWND hWnd)
{
    g_pD3D = Direct3DCreate9(D3D_SDK_VERSION);
    if (!g_pD3D) {
        return false;
    }

    ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
    g_d3dpp.Windowed = TRUE;
    g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
    g_d3dpp.EnableAutoDepthStencil = TRUE;
    g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;

    if (g_pD3D->CreateDevice(
        D3DADAPTER_DEFAULT,
        D3DDEVTYPE_HAL,
        hWnd,
        D3DCREATE_HARDWARE_VERTEXPROCESSING,
        &g_d3dpp,
        &g_pd3dDevice) < 0) {
        
        if (g_pD3D->CreateDevice(
            D3DADAPTER_DEFAULT,
            D3DDEVTYPE_HAL,
            hWnd,
            D3DCREATE_SOFTWARE_VERTEXPROCESSING,
            &g_d3dpp,
            &g_pd3dDevice) < 0) {
            return false;
        }
    }

    return true;
}

/**
 * Direct3D temizleme
 */
void CleanupD3D()
{
    if (g_pd3dDevice) {
        g_pd3dDevice->Release();
        g_pd3dDevice = nullptr;
    }
    if (g_pD3D) {
        g_pD3D->Release();
        g_pD3D = nullptr;
    }
}

/**
 * Render frame
 */
void RenderFrame()
{
    g_pd3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
    g_pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
    g_pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);

    D3DCOLOR clear_col = D3DCOLOR_RGBA(20, 20, 30, 255);
    g_pd3dDevice->Clear(0, nullptr, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, clear_col, 1.0f, 0);

    if (g_pd3dDevice->BeginScene() >= 0) {
        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // Ana window'u render et
        RenderMainWindow();

        ImGui::Render();
        ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
        g_pd3dDevice->EndScene();
    }

    g_pd3dDevice->Present(nullptr, nullptr, nullptr, nullptr);
}

/**
 * WndProc - Window procedure
 */
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) {
        return true;
    }

    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice && wParam != SIZE_MINIMIZED) {
            g_d3dpp.BackBufferWidth = LOWORD(lParam);
            g_d3dpp.BackBufferHeight = HIWORD(lParam);
            g_pd3dDevice->Reset(&g_d3dpp);
        }
        return 0;

    case WM_SYSCOMMAND:
        if ((wParam & 0xFFF0) == SC_KEYMENU) {
            return 0;
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

/**
 * Module base adresini bul
 */
DWORD_PTR FindModuleBase(const char* moduleName)
{
    if (!g_hProcess) return 0;

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(g_hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(g_hProcess, hMods[i], szModName, sizeof(szModName))) {
                std::string modName(szModName);
                if (modName.find(moduleName) != std::string::npos) {
                    MODULEINFO modInfo;
                    if (GetModuleInformation(g_hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                        g_moduleSize = modInfo.SizeOfImage;
                        return (DWORD_PTR)modInfo.lpBaseOfDll;
                    }
                }
            }
        }
    }
    return 0;
}

/**
 * Bellekten okuma
 */
bool ReadMemory(DWORD_PTR address, void* buffer, size_t size)
{
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(g_hProcess, (LPCVOID)address, buffer, size, &bytesRead) && bytesRead == size;
}

/**
 * KnightOnline'ya bağlan
 */
bool AttachToKO()
{
    DetachFromProcess();

    // Processleri listele
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    DWORD koPID = 0;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            char name[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, name, MAX_PATH, nullptr, nullptr);
            std::string procName(name);
            
            // KnightOnline.exe'yi ara (buyuk/kucuk harf duyarsiz)
            std::string lowerName = procName;
            for (auto& c : lowerName) c = tolower(c);
            if (lowerName.find("knightonline.exe") != std::string::npos ||
                lowerName.find("knight online") != std::string::npos) {
                koPID = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);

    if (koPID == 0) return false;

    // Process'e bağlan
    g_hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, koPID);
    if (!g_hProcess) return false;

    g_processId = koPID;
    g_attached = true;

    // Module base adresini bul
    g_moduleBase = FindModuleBase("KnightOnline");
    
    return true;
}

/**
 * Bağlantıyı kes
 */
void DetachFromProcess()
{
    if (g_hProcess && g_hProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hProcess);
        g_hProcess = nullptr;
    }
    g_attached = false;
    g_processId = 0;
    g_moduleBase = 0;
    memset(&g_KO_PTR, 0, sizeof(g_KO_PTR));
}

/**
 * Pattern Scan - Byte pattern ile arama
 */
bool PatternScan(const BYTE* pattern, const char* mask, DWORD_PTR& outAddress)
{
    if (!g_attached || g_moduleBase == 0) return false;

    std::vector<BYTE> buffer(g_moduleSize);
    if (!ReadMemory(g_moduleBase, buffer.data(), g_moduleSize)) {
        return false;
    }

    size_t patternLen = strlen(mask);
    for (size_t i = 0; i + patternLen <= buffer.size(); i++) {
        bool found = true;
        for (size_t j = 0; j < patternLen; j++) {
            if (mask[j] == 'x' && buffer[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            outAddress = g_moduleBase + i;
            return true;
        }
    }
    return false;
}

/**
 * Pointer tarama - hedef adrese işaret eden pointer'ları bul
 */
DWORD_PTR ScanForPointer(DWORD_PTR targetAddress, DWORD_PTR startAddr, DWORD size)
{
    if (!g_attached) return 0;

    std::vector<BYTE> buffer(size);
    if (!ReadMemory(startAddr, buffer.data(), size)) {
        return 0;
    }

    for (size_t i = 0; i + 4 <= buffer.size(); i += 4) {
        DWORD_PTR potentialPtr = *(DWORD_PTR*)&buffer[i];
        if (potentialPtr == targetAddress) {
            return startAddr + i;
        }
    }
    return 0;
}

/**
 * KO Pointer'larını otomatik tara
 * Pattern scanning ile KO'nun önemli pointer'larını bulur
 */
void ScanKOPointers()
{
    if (!g_attached || g_moduleBase == 0) {
        return;
    }

    g_autoScanning = true;
    g_foundPointers.clear();

    // Tüm module'ü tara
    DWORD scanSize = g_moduleSize;
    std::vector<BYTE> buffer(scanSize);
    
    if (!ReadMemory(g_moduleBase, buffer.data(), scanSize)) {
        g_autoScanning = false;
        return;
    }

    // Potansiyel global pointer'ları bul
    // KO'da genelde .data section'ında sabit pointer'lar var
    std::vector<DWORD_PTR> potentialPointers;
    
    // Data section genelde 0x00400000 + offset'te başlar
    // Static pointer pattern'ları ara
    for (size_t i = 0; i + 6 <= buffer.size(); i++) {
        // MOV EAX, [addr] pattern: A1 XX XX XX XX
        if (buffer[i] == 0xA1) {
            DWORD ptr = *(DWORD*)&buffer[i + 1];
            // Valid memory range kontrolü (genelde data section 0x00400000 - 0x02000000)
            if (ptr >= 0x00400000 && ptr < 0x02000000) {
                bool exists = false;
                for (auto& p : potentialPointers) {
                    if (p == ptr) { exists = true; break; }
                }
                if (!exists) potentialPointers.push_back(ptr);
            }
        }
        // MOV ECX, [addr] pattern: 8B 0D XX XX XX XX
        if (i + 5 < buffer.size() && buffer[i] == 0x8B && buffer[i+1] == 0x0D) {
            DWORD ptr = *(DWORD*)&buffer[i + 2];
            if (ptr >= 0x00400000 && ptr < 0x02000000) {
                bool exists = false;
                for (auto& p : potentialPointers) {
                    if (p == ptr) { exists = true; break; }
                }
                if (!exists) potentialPointers.push_back(ptr);
            }
        }
        // PUSH [addr] pattern: FF 35 XX XX XX XX
        if (i + 5 < buffer.size() && buffer[i] == 0xFF && buffer[i+1] == 0x35) {
            DWORD ptr = *(DWORD*)&buffer[i + 2];
            if (ptr >= 0x00400000 && ptr < 0x02000000) {
                bool exists = false;
                for (auto& p : potentialPointers) {
                    if (p == ptr) { exists = true; break; }
                }
                if (!exists) potentialPointers.push_back(ptr);
            }
        }
        // MOV EAX, [ESI+offset] gibi dolaylı referanslar için:
        // CMP DWORD PTR pattern: 83 3D XX XX XX XX
        if (i + 5 < buffer.size() && buffer[i] == 0x83 && buffer[i+1] == 0x3D) {
            DWORD ptr = *(DWORD*)&buffer[i + 2];
            if (ptr >= 0x00400000 && ptr < 0x02000000) {
                bool exists = false;
                for (auto& p : potentialPointers) {
                    if (p == ptr) { exists = true; break; }
                }
                if (!exists) potentialPointers.push_back(ptr);
            }
        }
    }

    // Bulunan pointer'ların değerlerini oku
    for (auto& ptr : potentialPointers) {
        DWORD value = 0;
        if (ReadMemory(ptr, &value, 4)) {
            // Geçerli bir pointer gibi görünüyorsa kaydet
            if (value > 0x10000) {
                FoundPointer fp;
                fp.address = ptr;
                fp.value = value;
                char name[64];
                snprintf(name, sizeof(name), "PTR_0x%08X", ptr);
                fp.name = name;
                g_foundPointers.push_back(fp);
            }
        }
    }

    // En olası KO pointer'larını ata
    // İlk bulduklarımızı ata, kullanıcı manuel değiştirebilir
    size_t idx = 0;
    if (!g_foundPointers.empty()) {
        if (g_KO_PTR.KO_PTR_CHR == 0 && idx < g_foundPointers.size()) {
            g_KO_PTR.KO_PTR_CHR = g_foundPointers[idx++].address;
        }
        if (g_KO_PTR.KO_PTR_PKT == 0 && idx < g_foundPointers.size()) {
            g_KO_PTR.KO_PTR_PKT = g_foundPointers[idx++].address;
        }
        if (g_KO_PTR.KO_PTR_DLG == 0 && idx < g_foundPointers.size()) {
            g_KO_PTR.KO_PTR_DLG = g_foundPointers[idx++].address;
        }
        if (g_KO_PTR.KO_SND_FNC == 0 && idx < g_foundPointers.size()) {
            g_KO_PTR.KO_SND_FNC = g_foundPointers[idx++].address;
        }
        if (g_KO_PTR.KO_RCV_FNC == 0 && idx < g_foundPointers.size()) {
            g_KO_PTR.KO_RCV_FNC = g_foundPointers[idx++].address;
        }
        if (g_KO_PTR.KO_FLDB == 0 && idx < g_foundPointers.size()) {
            g_KO_PTR.KO_FLDB = g_foundPointers[idx++].address;
        }
        if (g_KO_PTR.KO_FMBS == 0 && idx < g_foundPointers.size()) {
            g_KO_PTR.KO_FMBS = g_foundPointers[idx++].address;
        }
    }

    g_autoScanning = false;
}

/**
 * Pointer'ları dosyaya kaydet
 */
void SavePointersToFile()
{
    std::ofstream file("KO_Pointers.txt");
    if (file.is_open()) {
        file << "=== KnightOnline Pointers ===\n";
        file << "Module Base: 0x" << std::hex << g_moduleBase << std::dec << "\n";
        file << "Module Size: 0x" << std::hex << g_moduleSize << std::dec << "\n\n";
        
        file << "KO_PTR_CHR: 0x" << std::hex << g_KO_PTR.KO_PTR_CHR << std::dec << "\n";
        file << "KO_PTR_PKT: 0x" << std::hex << g_KO_PTR.KO_PTR_PKT << std::dec << "\n";
        file << "KO_PTR_DLG: 0x" << std::hex << g_KO_PTR.KO_PTR_DLG << std::dec << "\n";
        file << "KO_SND_FNC: 0x" << std::hex << g_KO_PTR.KO_SND_FNC << std::dec << "\n";
        file << "KO_RCV_FNC: 0x" << std::hex << g_KO_PTR.KO_RCV_FNC << std::dec << "\n";
        file << "KO_FLDB: 0x" << std::hex << g_KO_PTR.KO_FLDB << std::dec << "\n";
        file << "KO_FMBS: 0x" << std::hex << g_KO_PTR.KO_FMBS << std::dec << "\n";
        
        file << "\n=== Found Pointers ===\n";
        for (const auto& fp : g_foundPointers) {
            file << fp.name << ": 0x" << std::hex << fp.address << std::dec << " (Value: " << fp.value << ")\n";
        }
        
        file.close();
    }
}

/**
 * Pointer'ları dosyadan yükle
 */
void LoadPointersFromFile()
{
    std::ifstream file("KO_Pointers.txt");
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            // Basit parse - gerçekte daha iyi yapılmalı
            if (line.find("KO_PTR_CHR:") != std::string::npos) {
                sscanf(line.c_str(), "KO_PTR_CHR: 0x%lX", &g_KO_PTR.KO_PTR_CHR);
            }
            // Diğer pointer'lar da burada parse edilir
        }
        file.close();
    }
}

/**
 * Ana ImGui window render
 */
void RenderMainWindow()
{
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
    ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | 
                                    ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar;

    ImGui::Begin("KO PointerBulucu", nullptr, window_flags);

    // Menu bar
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Exit")) {
                PostQuitMessage(0);
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Tools")) {
            if (ImGui::MenuItem("Save Pointers")) {
                SavePointersToFile();
            }
            if (ImGui::MenuItem("Load Pointers")) {
                LoadPointersFromFile();
            }
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }

    // Sol panel - Durum
    ImGui::BeginChild("LeftPanel", ImVec2(300, 0), true);

    ImGui::Text("KnightOnline Status");
    ImGui::Separator();

    if (g_attached) {
        ImGui::TextColored(ImVec4(0, 1, 0, 1), "Attached to KO!");
        ImGui::Text("PID: %lu", g_processId);
        ImGui::Text("Module Base: 0x%08X", g_moduleBase);
        ImGui::Text("Module Size: 0x%08X", g_moduleSize);
        
        ImGui::Separator();
        
        if (ImGui::Button("Re-attach KO")) {
            AttachToKO();
        }
    } else {
        ImGui::TextColored(ImVec4(1, 0, 0, 1), "KnightOnline not found!");
        ImGui::Text("Start KO and click Attach");
        
        if (ImGui::Button("Attach to KO")) {
            AttachToKO();
        }
    }

    ImGui::EndChild();

    ImGui::SameLine();

    // Sağ panel - Pointer Scanner
    ImGui::BeginChild("RightPanel", ImVec2(0, 0), true);

    ImGui::Text("KO Pointer Scanner");
    ImGui::Separator();

    if (!g_attached) {
        ImGui::Text("Please attach to KnightOnline first");
        ImGui::EndChild();
        ImGui::End();
        return;
    }

    // KO Pointer'ları göster
    ImGui::Text("=== KO Pointers ===");
    
    // Auto Scan butonu
    if (ImGui::Button(g_autoScanning ? "Scanning..." : "Auto Scan KO Pointers")) {
        ScanKOPointers();
    }
    ImGui::SameLine();
    if (ImGui::Button("Reset All")) {
        memset(&g_KO_PTR, 0, sizeof(g_KO_PTR));
        g_foundPointers.clear();
    }
    
    ImGui::SameLine();
    if (ImGui::Button("Load Known Offsets")) {
        // Bilinen KO mutlak adreslerini direkt yükle
        g_KO_PTR.KO_PTR_CHR = KO_ADDR_CHR;
        g_KO_PTR.KO_PTR_DLG = KO_ADDR_DLG;
        g_KO_PTR.KO_PTR_PKT = KO_ADDR_PKT;
    }
    
    ImGui::Separator();
    
    // Pointer değerlerini göster (renkli)
    if (g_KO_PTR.KO_PTR_CHR != 0) {
        ImGui::TextColored(ImVec4(0, 1, 0, 1), "KO_PTR_CHR: 0x%08X", g_KO_PTR.KO_PTR_CHR);
    } else {
        ImGui::Text("KO_PTR_CHR: 0x%08X (Not Found)", g_KO_PTR.KO_PTR_CHR);
    }
    
    if (g_KO_PTR.KO_PTR_PKT != 0) {
        DWORD pktValue = 0;
        ReadMemory(g_KO_PTR.KO_PTR_PKT, &pktValue, 4);
        ImGui::TextColored(ImVec4(0, 1, 0, 1), "KO_PTR_PKT: 0x%08X -> [0x%08X]", g_KO_PTR.KO_PTR_PKT, pktValue);
    } else {
        ImGui::Text("KO_PTR_PKT: 0x%08X (Not Found)", g_KO_PTR.KO_PTR_PKT);
    }
    
    if (g_KO_PTR.KO_PTR_DLG != 0) {
        DWORD dlgValue = 0;
        ReadMemory(g_KO_PTR.KO_PTR_DLG, &dlgValue, 4);
        ImGui::TextColored(ImVec4(0, 1, 0, 1), "KO_PTR_DLG: 0x%08X -> [0x%08X]", g_KO_PTR.KO_PTR_DLG, dlgValue);
    } else {
        ImGui::Text("KO_PTR_DLG: 0x%08X (Not Found)", g_KO_PTR.KO_PTR_DLG);
    }
    
    if (g_KO_PTR.KO_SND_FNC != 0) {
        ImGui::TextColored(ImVec4(0, 1, 0, 1), "KO_SND_FNC: 0x%08X", g_KO_PTR.KO_SND_FNC);
    } else {
        ImGui::Text("KO_SND_FNC: 0x%08X (Not Found)", g_KO_PTR.KO_SND_FNC);
    }
    
    if (g_KO_PTR.KO_RCV_FNC != 0) {
        ImGui::TextColored(ImVec4(0, 1, 0, 1), "KO_RCV_FNC: 0x%08X", g_KO_PTR.KO_RCV_FNC);
    } else {
        ImGui::Text("KO_RCV_FNC: 0x%08X (Not Found)", g_KO_PTR.KO_RCV_FNC);
    }
    
    if (g_KO_PTR.KO_FLDB != 0) {
        ImGui::TextColored(ImVec4(0, 1, 0, 1), "KO_FLDB: 0x%08X", g_KO_PTR.KO_FLDB);
    } else {
        ImGui::Text("KO_FLDB: 0x%08X (Not Found)", g_KO_PTR.KO_FLDB);
    }
    
    if (g_KO_PTR.KO_FMBS != 0) {
        ImGui::TextColored(ImVec4(0, 1, 0, 1), "KO_FMBS: 0x%08X", g_KO_PTR.KO_FMBS);
    } else {
        ImGui::Text("KO_FMBS: 0x%08X (Not Found)", g_KO_PTR.KO_FMBS);
    }

    ImGui::Separator();

    // Manuel pointer giriş
    ImGui::Text("Manual Pointer Entry:");
    
    static DWORD chrAddr = 0;
    ImGui::InputScalar("KO_PTR_CHR", ImGuiDataType_U32, &chrAddr, nullptr, nullptr, "%08X", ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    if (ImGui::Button("Set CHR")) {
        g_KO_PTR.KO_PTR_CHR = chrAddr;
    }

    static DWORD pktAddr = 0;
    ImGui::InputScalar("KO_PTR_PKT", ImGuiDataType_U32, &pktAddr, nullptr, nullptr, "%08X", ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    if (ImGui::Button("Set PKT")) {
        g_KO_PTR.KO_PTR_PKT = pktAddr;
    }

    ImGui::Separator();

    // Pointer bulma
    ImGui::Text("Find Pointer to Address:");
    static DWORD targetAddr = 0;
    ImGui::InputScalar("Target Address", ImGuiDataType_U32, &targetAddr, nullptr, nullptr, "%08X", ImGuiInputTextFlags_CharsHexadecimal);
    
    if (ImGui::Button("Find Pointers")) {
        DWORD_PTR found = ScanForPointer(targetAddr, g_moduleBase, g_moduleSize);
        if (found) {
            FoundPointer fp;
            fp.name = "Found Pointer";
            fp.address = found;
            fp.value = 0;
            g_foundPointers.push_back(fp);
        }
    }

    ImGui::Text("Found %zu pointers", g_foundPointers.size());

    ImGui::Separator();
    ImGui::Text("Found Pointers:");
    
    if (ImGui::BeginChild("FoundList", ImVec2(0, 150))) {
        for (size_t i = 0; i < g_foundPointers.size(); i++) {
            const auto& fp = g_foundPointers[i];
            char label[128];
            snprintf(label, sizeof(label), "0x%08X - %s", fp.address, fp.name.c_str());
            ImGui::Selectable(label);
        }
    }
    ImGui::EndChild();

    ImGui::EndChild();

    ImGui::End();
}
