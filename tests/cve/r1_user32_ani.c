/* R-1 regression: user32.dll animated-cursor (ANI) parsing in
   windows/core/ntuser/client/acons.c, reached from LoadCursorFromFile / LoadImage for any
   .ani file a program opens (MS07-017 / MS05-002 class).

   extracted.c (written by tests/test_cve.py) holds LoadAniIcon and the RIFF and file-map
   helpers verbatim, original or patched. Frame images and the final ACON are outside
   this harness: ReadIconFromFileMap is modelled as "consume the chunk, return a frame
   handle" and CreateAniIcon as "return a cursor handle"; both record what they were given.
   The file is mapped in an allocation of exactly its size, so any read past its end is
   seen by AddressSanitizer. Every chunk body below is filler: the malformed files differ
   from the valid one only in chunk sizes and order.

   usage: r1_user32_ani valid|anih-size|rate-size|seq-size|order|frames|truncated
   exit 0 = the expectation for this mode holds */
#include "nt_shim.h"

typedef DWORD FOURCC;
typedef BYTE *PBYTE;
typedef void *HCURSOR, *HICON;
#define CURSOR_ALWAYSDESTROY 0x01
#define LR_GLOBAL 0x8000
typedef DWORD JIF, *PJIF;
typedef struct _RTAG { FOURCC ckID; DWORD ckSize; } RTAG, *PRTAG;
typedef struct _ANIHEADER {
    DWORD cbSizeof, cFrames, cSteps, cx, cy, cBitCount, cPlanes;
    JIF jifRate;
    DWORD fl;
} ANIHEADER, *PANIHEADER;
typedef struct _FILEINFO { LPBYTE pFileMap, pFilePtr, pFileEnd; LPCWSTR pszName; } FILEINFO, *PFILEINFO;

#define UNALIGNED
#define mmioFOURCC(a, b, c, d) ((DWORD)(BYTE)(a) | ((DWORD)(BYTE)(b) << 8) | ((DWORD)(BYTE)(c) << 16) | ((DWORD)(BYTE)(d) << 24))
#define FOURCC_RIFF mmioFOURCC('R', 'I', 'F', 'F')
#define FOURCC_LIST mmioFOURCC('L', 'I', 'S', 'T')
#define FOURCC_ACON mmioFOURCC('A', 'C', 'O', 'N')
#define FOURCC_anih mmioFOURCC('a', 'n', 'i', 'h')
#define FOURCC_rate mmioFOURCC('r', 'a', 't', 'e')
#define FOURCC_seq  mmioFOURCC('s', 'e', 'q', ' ')
#define FOURCC_fram mmioFOURCC('f', 'r', 'a', 'm')
#define FOURCC_icon mmioFOURCC('i', 'c', 'o', 'n')
#define AF_ICON 0x0001L
#define AF_SEQUENCE 0x0002L
#define HEAP_ZERO_MEMORY 0x00000008
#define RIP_WARNING 0
#define RIPMSG0(f, s) ((void)0)
#define RIPMSG2(f, s, a, b) ((void)0)
#define UserAssert(e) ASSERT(e)
#define NATURAL_ALIGNED_PTR(t, p) (p)
#ifndef RtlCopyMemory
#define RtlCopyMemory(d, s, n) memcpy((d), (s), (n))
#endif

static PVOID UserLocalAlloc(DWORD flags, SIZE_T cb) { (void)flags; return calloc(1, cb ? cb : 1); }
static void UserLocalFree(PVOID p) { free(p); }

static int frames_read, frames_destroyed, made_acon, acon_frames, acon_steps;
static BOOL NtUserDestroyCursor(HCURSOR h, DWORD flags) { (void)h; (void)flags; frames_destroyed++; return TRUE; }

/* Model: a frame chunk is consumed as a unit; its image is opaque here. */
static HCURSOR ReadIconFromFileMap(PFILEINFO pfi, int cbSize, DWORD cx, DWORD cy, DWORD flags)
{
    (void)cx; (void)cy; (void)flags;
    if (cbSize < 0 || (SIZE_T)cbSize > (SIZE_T)(pfi->pFileEnd - pfi->pFilePtr)) return NULL;
    pfi->pFilePtr += (cbSize + 1) & ~1;
    if (pfi->pFilePtr > pfi->pFileEnd) return NULL;
    return (HCURSOR)(ULONG_PTR)(0x1000 + ++frames_read);
}

static HCURSOR CreateAniIcon(LPCWSTR pszName, LPWSTR rt, int cicur, DWORD *aicur, int cpcur, HCURSOR *ahcur,
                             JIF jifRate, PJIF ajifRate, BOOL fGlobal)
{
    (void)pszName; (void)rt; (void)aicur; (void)ahcur; (void)jifRate; (void)ajifRate; (void)fGlobal;
    made_acon++; acon_frames = cpcur; acon_steps = cicur;
    return (HCURSOR)(ULONG_PTR)0xACE;
}

#include "extracted.c"

/* A small RIFF writer. */
static BYTE file[4096];
static DWORD used;
static void put32(DWORD v) { memcpy(file + used, &v, 4); used += 4; }
static void chunk(FOURCC id, DWORD declared, DWORD actual)
{
    put32(id); put32(declared);
    memset(file + used, 0x11, actual); used += (actual + 1) & ~1u;
}
static void anih(DWORD declared, DWORD frames, DWORD steps)
{
    ANIHEADER h;
    memset(&h, 0, sizeof(h));
    h.cbSizeof = sizeof(h); h.cFrames = frames; h.cSteps = steps; h.jifRate = 6; h.fl = AF_ICON | AF_SEQUENCE;
    put32(FOURCC_anih); put32(declared);
    memcpy(file + used, &h, sizeof(h)); used += sizeof(h);
    if (declared > sizeof(h)) { memset(file + used, 0x11, declared - sizeof(h)); used += declared - sizeof(h); }
}
static void fram(int icons)
{
    int i;
    put32(FOURCC_LIST); put32(4 + icons * 12); put32(FOURCC_fram);
    for (i = 0; i < icons; i++) chunk(FOURCC_icon, 4, 4);
}

static HICON load(void)
{
    FILEINFO fi;
    BYTE *map;
    HICON h;
    DWORD riff = used - 8;
    memcpy(file + 4, &riff, 4);
    map = malloc(used);                  /* exactly the file's size */
    memcpy(map, file, used);
    fi.pFileMap = map; fi.pFileEnd = map + used; fi.pFilePtr = map; fi.pszName = NULL;
    h = LoadAniIcon(&fi, NULL, 32, 32, 0);
    free(map);
    return h;
}

static void begin(void)
{
    used = 0; frames_read = frames_destroyed = made_acon = 0;
    put32(FOURCC_RIFF); put32(0); put32(FOURCC_ACON);
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "";
    HICON h;
    begin();
    if (!strcmp(mode, "valid")) {
        /* Two frames, two steps, rate and sequence tables of exactly their size. */
        anih(sizeof(ANIHEADER), 2, 2);
        put32(FOURCC_rate); put32(8); put32(6); put32(12);
        put32(FOURCC_seq); put32(8); put32(1); put32(0);
        fram(2);
        h = load();
        printf("handle=%p frames=%d acon=%d/%d\n", h, frames_read, acon_frames, acon_steps);
        return !(h && frames_read == 2 && made_acon == 1 && acon_frames == 2 && acon_steps == 2);
    }
    if (!strcmp(mode, "anih-size")) {
        /* An 'anih' chunk declared larger than the ANIHEADER it is copied into. */
        anih(sizeof(ANIHEADER) + 64, 1, 1); fram(1);
        h = load();
        return h != NULL || made_acon;
    }
    if (!strcmp(mode, "rate-size")) {
        /* A 'rate' chunk larger than the one-step rate table. */
        anih(sizeof(ANIHEADER), 1, 1); chunk(FOURCC_rate, 64, 64); fram(1);
        h = load();
        return h != NULL || made_acon;
    }
    if (!strcmp(mode, "seq-size")) {
        /* A 'seq ' chunk larger than the one-step sequence table. */
        anih(sizeof(ANIHEADER), 1, 1); chunk(FOURCC_seq, 64, 64); fram(1);
        h = load();
        return h != NULL || made_acon;
    }
    if (!strcmp(mode, "order")) {
        /* 'rate' before any 'anih' has sized the tables. Patched build only: the original
           computes the table address from a NULL table and an uninitialized count. */
        chunk(FOURCC_rate, 8, 8); anih(sizeof(ANIHEADER), 1, 1); fram(1);
        h = load();
        return h != NULL || made_acon;
    }
    if (!strcmp(mode, "frames")) {
        /* More 'icon' frames than 'anih' declared. */
        anih(sizeof(ANIHEADER), 1, 1); fram(4);
        h = load();
        return h != NULL || made_acon || frames_destroyed != frames_read;
    }
    if (!strcmp(mode, "truncated")) {
        /* A chunk that claims more bytes than the file holds. */
        anih(sizeof(ANIHEADER), 1, 1);
        put32(FOURCC_LIST); put32(0x7ffffff0); put32(FOURCC_fram);
        h = load();
        return h != NULL || made_acon;
    }
    return 2;
}
