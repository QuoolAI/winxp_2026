/* RoverAIBand.dll exports beyond the standard COM entry points. */
#ifndef ROVER_BAND_H
#define ROVER_BAND_H
#include <windows.h>

extern const CLSID CLSID_RoverAIBand;
extern const CLSID CLSID_RoverAISearchBand;
extern const CLSID CLSID_XpSearchBand;
extern const CLSID CLSID_RoverAIFileSearchBand;
extern const CLSID CLSID_XpFileSearchBand;
STDAPI RoverAIReplaceSearch(BOOL enable);
#endif
