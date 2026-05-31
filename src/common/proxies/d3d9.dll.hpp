// ReSharper disable CppNonInlineFunctionDefinitionInHeaderFile
#pragma once
#include "proxies/proxy_base.hpp"

namespace proxy {
	void on_direct3d9_created(IDirect3D9* direct3d9);

}

extern "C" {
	int PROXY_API D3DPERF_BeginEvent_ZP(D3DCOLOR col, LPCWSTR wszName) {
		static auto func = proxy::get_export<decltype(&D3DPERF_BeginEvent_ZP)>("d3d9.dll", "D3DPERF_BeginEvent");
		return func(col, wszName);
	}
#	pragma comment(linker, PROXY_EXPORT(D3DPERF_BeginEvent, 8, 27))

	int PROXY_API D3DPERF_EndEvent_ZP(void) {
		static auto func = proxy::get_export<decltype(&D3DPERF_EndEvent_ZP)>("d3d9.dll", "D3DPERF_EndEvent");
		return func();
	}
#	pragma comment(linker, PROXY_EXPORT(D3DPERF_EndEvent, 0, 28))

	IDirect3D9* PROXY_API Direct3DCreate9_ZP(UINT SDKVersion) {
		static auto func = proxy::get_export<decltype(&Direct3DCreate9_ZP)>("d3d9.dll", "Direct3DCreate9");
		auto* const direct3d9 = func(SDKVersion);
		proxy::on_direct3d9_created(direct3d9);
		return direct3d9;
	}
#	pragma comment(linker, PROXY_EXPORT(Direct3DCreate9, 4, 37))
}
