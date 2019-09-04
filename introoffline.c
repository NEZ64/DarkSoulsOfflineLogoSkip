/*
 *    build cmd with mingw32:
 *        gcc -Wall -Wl,--out-implib,libmessage.a -Wl,--enable-stdcall-fixup
 *            exports.DEF introoffline.c -shared -o DINPUT8.dll
 *
 */

#include <windows.h>
#include <string.h>

/*
 *    This patching mechanism taken from:
 *        https://github.com/bladecoding/DarkSouls3RemoveIntroScreens/blob/master/SoulsSkipIntroScreen/dllmain.cpp
 *
 *
 */
struct patch {
    DWORD rel_addr;
    DWORD size;
    char patch[50];
    char orig[50];
};

typedef HRESULT (WINAPI *dinp8crt_t)(HINSTANCE, DWORD, REFIID,
				     LPVOID *, LPUNKNOWN);
dinp8crt_t oDirectInput8Create;

__attribute__ ((dllexport))
HRESULT WINAPI DirectInput8Create(HINSTANCE inst, DWORD ver, REFIID id,
				  LPVOID *pout, LPUNKNOWN outer)
{
    return oDirectInput8Create(inst, ver, id, pout, outer);
}

void setup_d8proxy(void)
{
    char syspath[320];
    GetSystemDirectoryA(syspath, 320);
    strcat(syspath, "\\dinput8.dll");
    HMODULE mod = LoadLibraryA(syspath);
    oDirectInput8Create = (dinp8crt_t)GetProcAddress(mod, "DirectInput8Create");
}

void attach_hook(void)
{
    {
	/* no logo modification    */
        struct patch patches[] =
	{
	    /* release */
	    {
		0x8320b0, 7,
		{0xe9, 0x27, 0x01, 0x00, 0x00, 0x90, 0x90,},
		{0xff, 0x24, 0x85, 0x24, 0x22, 0xc3, 0x00,},
	    },
	    {
		0x8322b3, 2,
		{0x90, 0x90,},
		{0x74, 0x0d,},
	    },
	    /* debug */
	    {
		0x831b30, 7,
		{0xe9, 0x27, 0x01, 0x00, 0x00, 0x90, 0x90,},
		{0xff, 0x24, 0x85, 0xa4, 0x1c, 0xc3, 0x00,},
	    },
	    {
		0x831d33, 2,
		{0x90, 0x90,},
		{0x74, 0x0d,},
	    },
	    /* steamworks */
	    {
		0x831180, 7,
		{0xe9, 0x27, 0x01, 0x00, 0x00, 0x90, 0x90,},
		{0xff, 0x24, 0x85, 0xf4, 0x12, 0xc3, 0x00,},
	    },
	    {
		0x831383, 2,
		{0x90, 0x90,},
		{0x74, 0x0d,},
	    },
	};
	
	void *base_addr = GetModuleHandle(NULL);
	for (int i = 0; i < (sizeof(patches) / sizeof(patches[0])); i++) {
	    struct patch *patch = patches + i;
	    void *addr = base_addr + patch->rel_addr;
	    DWORD size = patch->size;

	    if (memcmp(addr, patch->orig, size) == 0) {
		DWORD old;
		VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &old);
		memcpy(addr, patch->patch, size);
		VirtualProtect(addr, size, old, &old);
	    }
	}
    }

    {
	/* setting game to offline */
	static char hook_bytes[] =
	{
	    0x05, 0x4c, 0x0b, 0x00, 0x00,   /* add eax, 0xb4c          */
	    0xc6, 0x00, 0x01,               /* mov byte ptr [eax], 0x1 */
	    0x40,                           /* inc eax                 */
            0xc6, 0x00, 0x00,               /* mov byte ptr [eax], 0x0 */
	    0xe8, 0x00, 0x00, 0x00, 0x00,   /* call original           */
	    0xe9, 0x00, 0x00, 0x00, 0x00,   /* jmp back to game code   */
	};
	void *hook = hook_bytes;

	void *fps_injct_pnt;
        char *reg_injct_pnt;
	DWORD ver_num = *(DWORD*) 0x400080;
	if (ver_num == 0xfc293654) {
            /* release */
	    fps_injct_pnt = (void*)0xebba94;
            reg_injct_pnt = (char*)0x7068cf;
        } else if (ver_num == 0xce9634b4) {
            /* debug */
	    fps_injct_pnt = (void*)0xebe952;
            reg_injct_pnt = (char*)0x7078df;
	} else if (ver_num == 0xe91b11e2) {
            /* steamworks (+cracked?) */
	    fps_injct_pnt = (void*)0xeba704;
            reg_injct_pnt = (char*)0x7069cf;
        } else
	    return;

	DWORD op;
	VirtualProtect(hook_bytes, sizeof(hook_bytes),
		       PAGE_EXECUTE_READWRITE, &op);
	VirtualProtect(fps_injct_pnt, 5, PAGE_EXECUTE_READWRITE, &op);

	int *offset_loc;
	int  new_offset;
	/* get address the  game is supposed to call */
	offset_loc   = fps_injct_pnt + 1;
	new_offset   = *offset_loc;
	new_offset  += (int)fps_injct_pnt + 5;
	new_offset  -= (int)hook + 17;
	offset_loc   = hook + 13;
	*offset_loc  = new_offset;

	/* get the address our code jumps back to */
	new_offset   = (int)fps_injct_pnt + 5;
	new_offset  -= (int)hook + 22;
	offset_loc   = hook + 18;
	*offset_loc  = new_offset;

	/* write the jump to our code over the game's */
	new_offset   = (hook - fps_injct_pnt) - 5;
	*(char*) fps_injct_pnt++ = 0xe9;
	offset_loc   = fps_injct_pnt;
	*offset_loc  = new_offset;

	VirtualProtect(fps_injct_pnt, 5, op, &op);

        /* make the game set itself to 'regular' offline
         * mode, i.e. as if offline on steam
         */
        VirtualProtect(reg_injct_pnt, 1,
                       PAGE_EXECUTE_READWRITE, &op);
        *reg_injct_pnt = 0x00;
        VirtualProtect(reg_injct_pnt, 1, op, &op);
    }
}

BOOL APIENTRY DllMain(HMODULE mod, DWORD reason,
		      LPVOID res)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
	setup_d8proxy();
	attach_hook();
	break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
	break;
    }
    return TRUE;
}
