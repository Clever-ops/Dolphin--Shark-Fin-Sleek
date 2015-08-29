// Copyright 2015 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#include "VideoBackends/D3D/D3DBase.h"
#include "VideoBackends/D3D/D3DTexture.h"
#include "VideoBackends/D3D/D3DUtil.h"
#include "VideoBackends/D3D/FramebufferManager.h"
#include "VideoBackends/D3D/Render.h"
#include "VideoBackends/D3D/VRD3D.h"
#include "VideoCommon/VideoConfig.h"
#include "VideoCommon/VR.h"

// Oculus Rift
#ifdef OVR_MAJOR_VERSION

#if OVR_MAJOR_VERSION <= 5
ovrD3D11Texture g_eye_texture[2];
#else
//------------------------------------------------------------
// ovrSwapTextureSet wrapper class that also maintains the render target views
// needed for D3D11 rendering.
struct OculusTexture
{
	ovrSwapTextureSet      * TextureSet;
	ID3D11RenderTargetView * TexRtv[3];

	OculusTexture(ovrHmd hmd, ovrSizei size)
	{
		D3D11_TEXTURE2D_DESC dsDesc;
		dsDesc.Width = size.w;
		dsDesc.Height = size.h;
		dsDesc.MipLevels = 1;
		dsDesc.ArraySize = 1;
		dsDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM_SRGB;
		dsDesc.SampleDesc.Count = 1;   // No multi-sampling allowed
		dsDesc.SampleDesc.Quality = 0;
		dsDesc.Usage = D3D11_USAGE_DEFAULT;
		dsDesc.CPUAccessFlags = 0;
		dsDesc.MiscFlags = 0;
		dsDesc.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET;

		ovrHmd_CreateSwapTextureSetD3D11(hmd, DX11::D3D::device, &dsDesc, &TextureSet);
		for (int i = 0; i < TextureSet->TextureCount; ++i)
		{
			ovrD3D11Texture* tex = (ovrD3D11Texture*)&TextureSet->Textures[i];
			DX11::D3D::device->CreateRenderTargetView(tex->D3D11.pTexture, nullptr, &TexRtv[i]);
		}
	}

	void AdvanceToNextTexture()
	{
		TextureSet->CurrentIndex = (TextureSet->CurrentIndex + 1) % TextureSet->TextureCount;
	}
	void Release(ovrHmd hmd)
	{
		ovrHmd_DestroySwapTextureSet(hmd, TextureSet);
	}
};

OculusTexture *pEyeRenderTexture[2];
ovrRecti       eyeRenderViewport[2];
#endif

#endif


namespace DX11
{
	
void VR_ConfigureHMD()
{
#ifdef OVR_MAJOR_VERSION
#if OVR_MAJOR_VERSION <= 5
	ovrD3D11Config cfg;
	cfg.D3D11.Header.API = ovrRenderAPI_D3D11;
#ifdef OCULUSSDK044ORABOVE
	cfg.D3D11.Header.BackBufferSize.w = hmdDesc.Resolution.w;
	cfg.D3D11.Header.BackBufferSize.h = hmdDesc.Resolution.h;
#else
	cfg.D3D11.Header.RTSize.w = hmdDesc.Resolution.w;
	cfg.D3D11.Header.RTSize.h = hmdDesc.Resolution.h;
#endif
	cfg.D3D11.Header.Multisample = 0;
	cfg.D3D11.pDevice = D3D::device;
	cfg.D3D11.pDeviceContext = D3D::context;
	cfg.D3D11.pSwapChain = D3D::swapchain;
	cfg.D3D11.pBackBufferRT = D3D::GetBackBuffer()->GetRTV();
	if (g_is_direct_mode) //If Rift is in Direct Mode
	{
		//To do: This is a bit of a hack, but I haven't found any problems with this.  
		//If we don't want to do this, large changes will be needed to init sequence.
		D3D::UnloadDXGI();  //Unload CreateDXGIFactory() before ovrHmd_AttachToWindow, or else direct mode won't work.
		ovrHmd_AttachToWindow(hmd, D3D::hWnd, nullptr, nullptr); //Attach to Direct Mode.
		D3D::LoadDXGI();
	}
	int caps = 0;
#if OVR_MAJOR_VERSION <= 4
	if (g_Config.bChromatic)
		caps |= ovrDistortionCap_Chromatic;
#endif
	if (g_Config.bTimewarp)
		caps |= ovrDistortionCap_TimeWarp;
	if (g_Config.bVignette)
		caps |= ovrDistortionCap_Vignette;
	if (g_Config.bNoRestore)
		caps |= ovrDistortionCap_NoRestore;
	if (g_Config.bFlipVertical)
		caps |= ovrDistortionCap_FlipInput;
	if (g_Config.bSRGB)
		caps |= ovrDistortionCap_SRGB;
	if (g_Config.bOverdrive)
		caps |= ovrDistortionCap_Overdrive;
	if (g_Config.bHqDistortion)
		caps |= ovrDistortionCap_HqDistortion;
	ovrHmd_ConfigureRendering(hmd, &cfg.Config, caps,
		g_eye_fov, g_eye_render_desc);
#if OVR_MAJOR_VERSION <= 4
	ovrhmd_EnableHSWDisplaySDKRender(hmd, false); //Disable Health and Safety Warning.
#endif

#else
	for (int i = 0; i < ovrEye_Count; ++i)
		g_eye_render_desc[i] = ovrHmd_GetRenderDesc(hmd, (ovrEyeType)i, g_eye_fov[i]);
#endif
#endif
}

void VR_StartFramebuffer()
{
	if (g_has_vr920)
	{
#ifdef _WIN32
		VR920_StartStereo3D();
#endif
	}
#ifdef OVR_MAJOR_VERSION
	else if (g_has_rift)
	{

#if OVR_MAJOR_VERSION <= 5
		for (int eye = 0; eye < 2; ++eye)
		{
			FramebufferManager::m_efb.m_frontBuffer[eye] = nullptr;
			// init to null
		}
		// In Oculus SDK 0.5.0.1 or below we need to create our own textures for eye render targets
		ID3D11Texture2D* buf;
		DXGI_SAMPLE_DESC sample_desc = D3D::GetAAMode(g_ActiveConfig.iMultisampleMode);
		D3D11_TEXTURE2D_DESC texdesc = CD3D11_TEXTURE2D_DESC(DXGI_FORMAT_R8G8B8A8_UNORM, FramebufferManager::m_target_width, FramebufferManager::m_target_height, 1, 1, D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET, D3D11_USAGE_DEFAULT, 0, 1, sample_desc.Quality);
		for (int eye = 0; eye<2; ++eye)
		{
			HRESULT hr = D3D::device->CreateTexture2D(&texdesc, nullptr, &buf);
			CHECK(hr == S_OK, "create Oculus Rift eye texture (size: %dx%d; hr=%#x)", FramebufferManager::m_target_width, FramebufferManager::m_target_height, hr);
			FramebufferManager::m_efb.m_frontBuffer[eye] = new D3DTexture2D(buf, (D3D11_BIND_FLAG)(D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET), DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_FORMAT_UNKNOWN, DXGI_FORMAT_R8G8B8A8_UNORM, false);
			CHECK(FramebufferManager::m_efb.m_frontBuffer[eye] != nullptr, "create Oculus Rift eye texture (size: %dx%d)", FramebufferManager::m_target_width, FramebufferManager::m_target_height);
			SAFE_RELEASE(buf);
		}
		D3D::SetDebugObjectName((ID3D11DeviceChild*)FramebufferManager::m_efb.m_frontBuffer[0]->GetTex(), "Left eye color texture");
		D3D::SetDebugObjectName((ID3D11DeviceChild*)FramebufferManager::m_efb.m_frontBuffer[0]->GetSRV(), "Left eye color texture shader resource view");
		D3D::SetDebugObjectName((ID3D11DeviceChild*)FramebufferManager::m_efb.m_frontBuffer[0]->GetRTV(), "Left eye color texture render target view");
		D3D::SetDebugObjectName((ID3D11DeviceChild*)FramebufferManager::m_efb.m_frontBuffer[1]->GetTex(), "Right eye color texture");
		D3D::SetDebugObjectName((ID3D11DeviceChild*)FramebufferManager::m_efb.m_frontBuffer[1]->GetSRV(), "Right eye color texture shader resource view");
		D3D::SetDebugObjectName((ID3D11DeviceChild*)FramebufferManager::m_efb.m_frontBuffer[1]->GetRTV(), "Right eye color texture render target view");

		// In Oculus SDK 0.5.0.1 and below, we need to keep descriptions of our eye textures to pass to ovrHmd_EndFrame()
		g_eye_texture[0].D3D11.Header.API = ovrRenderAPI_D3D11;
		g_eye_texture[0].D3D11.Header.TextureSize.w = Renderer::GetTargetWidth();
		g_eye_texture[0].D3D11.Header.TextureSize.h = Renderer::GetTargetHeight();
		g_eye_texture[0].D3D11.Header.RenderViewport.Pos.x = 0;
		g_eye_texture[0].D3D11.Header.RenderViewport.Pos.y = 0;
		g_eye_texture[0].D3D11.Header.RenderViewport.Size.w = Renderer::GetTargetWidth();
		g_eye_texture[0].D3D11.Header.RenderViewport.Size.h = Renderer::GetTargetHeight();
		g_eye_texture[0].D3D11.pTexture = FramebufferManager::m_efb.m_frontBuffer[0]->GetTex();
		g_eye_texture[0].D3D11.pSRView = FramebufferManager::m_efb.m_frontBuffer[0]->GetSRV();
		// If we are rendering in mono then use the same texture for both eyes, otherwise use a different eye texture
		g_eye_texture[1] = g_eye_texture[0];
		if (g_ActiveConfig.iStereoMode == STEREO_OCULUS)
		{
			g_eye_texture[1].D3D11.pTexture = FramebufferManager::m_efb.m_frontBuffer[1]->GetTex();
			g_eye_texture[1].D3D11.pSRView = FramebufferManager::m_efb.m_frontBuffer[1]->GetSRV();
		}
#else
		// On Oculus SDK 0.6.0 and above, get Oculus to create our textures for us. And remember the viewport.
		for (int eye = 0; eye < 2; eye++)
		{
			ovrSizei target_size;
			target_size.w = Renderer::GetTargetWidth();
			target_size.h = Renderer::GetTargetHeight();
			pEyeRenderTexture[eye] = new OculusTexture(hmd, target_size);
			eyeRenderViewport[eye].Pos.x = 0;
			eyeRenderViewport[eye].Pos.y = 0;
			eyeRenderViewport[eye].Size = target_size;
		}

#endif
	}
#endif
}

void VR_StopFramebuffer()
{
#if defined(OVR_MAJOR_VERSION) && OVR_MAJOR_VERSION >= 6
	// On Oculus SDK 0.6.0 and above, we need to destroy the eye textures Oculus created for us.
	for (int eye = 0; eye < 2; eye++)
	{
		if (pEyeRenderTexture[eye])
		{
			pEyeRenderTexture[eye]->Release(hmd);
			delete pEyeRenderTexture[eye];
			pEyeRenderTexture[eye] = nullptr;
		}
	}
#else
	SAFE_RELEASE(FramebufferManager::m_efb.m_frontBuffer[0]);
	SAFE_RELEASE(FramebufferManager::m_efb.m_frontBuffer[1]);
#endif
}

void VR_BeginFrame()
{
	// At the start of a frame, we get the frame timing and begin the frame.
#ifdef OVR_MAJOR_VERSION
	if (g_has_rift)
	{
#if OVR_MAJOR_VERSION >= 6
		++g_ovr_frameindex;
		// On Oculus SDK 0.6.0 and above, we get the frame timing manually, then swap each eye texture 
		g_rift_frame_timing = ovrHmd_GetFrameTiming(hmd, 0);
		for (int eye = 0; eye < 2; eye++)
		{
			// Increment to use next texture, just before writing
			pEyeRenderTexture[eye]->AdvanceToNextTexture();
		}
#else
		g_rift_frame_timing = ovrHmd_BeginFrame(hmd, ++g_ovr_frameindex);
#endif
	}
#endif
}

void VR_RenderToEyebuffer(int eye)
{
#ifdef OVR_MAJOR_VERSION
#if OVR_MAJOR_VERSION >= 6
	D3D::context->OMSetRenderTargets(1, &pEyeRenderTexture[eye]->TexRtv[pEyeRenderTexture[eye]->TextureSet->CurrentIndex], nullptr);
#else
	D3D::context->OMSetRenderTargets(1, &FramebufferManager::m_efb.m_frontBuffer[0]->GetRTV(), nullptr);
#endif
#endif
}

void VR_PresentHMDFrame()
{
#ifdef OVR_MAJOR_VERSION
	if (g_has_rift)
	{
		//ovrHmd_EndEyeRender(hmd, ovrEye_Left, g_left_eye_pose, &FramebufferManager::m_eye_texture[ovrEye_Left].Texture);
		//ovrHmd_EndEyeRender(hmd, ovrEye_Right, g_right_eye_pose, &FramebufferManager::m_eye_texture[ovrEye_Right].Texture);

		//Change to compatible D3D Blend State:
		//Some games (e.g. Paper Mario) do not use a Blend State that is compatible
		//with the Oculus Rift's SDK.  They set RenderTargetWriteMask to 0,
		//which masks out the call's Pixel Shader stage.  This also seems inefficient
		// from a rendering point of view.  Could this be an area Dolphin could be optimized?
		//To Do: Only use this when needed?  Is this slow?
		ID3D11BlendState* g_pOculusRiftBlendState = NULL;

		D3D11_BLEND_DESC oculusBlendDesc;
		ZeroMemory(&oculusBlendDesc, sizeof(D3D11_BLEND_DESC));
		oculusBlendDesc.AlphaToCoverageEnable = FALSE;
		oculusBlendDesc.IndependentBlendEnable = FALSE;
		oculusBlendDesc.RenderTarget[0].BlendEnable = FALSE;
		oculusBlendDesc.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;

		HRESULT hr = D3D::device->CreateBlendState(&oculusBlendDesc, &g_pOculusRiftBlendState);
		if (FAILED(hr)) PanicAlert("Failed to create blend state at %s %d\n", __FILE__, __LINE__);
		D3D::SetDebugObjectName((ID3D11DeviceChild*)g_pOculusRiftBlendState, "blend state used to make sure rift draw call works");

		D3D::context->OMSetBlendState(g_pOculusRiftBlendState, NULL, 0xFFFFFFFF);

#if OVR_MAJOR_VERSION <= 5
		// Let OVR do distortion rendering, Present and flush/sync.
		ovrHmd_EndFrame(hmd, g_eye_poses, &g_eye_texture[0].Texture);
#else
		ovrLayerEyeFov ld;
		ld.Header.Type = ovrLayerType_EyeFov;
		ld.Header.Flags = 0;
		for (int eye = 0; eye < 2; eye++)
		{
			ld.ColorTexture[eye] = pEyeRenderTexture[eye]->TextureSet;
			ld.Viewport[eye] = eyeRenderViewport[eye];
			ld.Fov[eye] = g_eye_fov[eye];
			ld.RenderPose[eye] = g_eye_poses[eye];
		}
		ovrLayerHeader* layers = &ld.Header;
		ovrResult result = ovrHmd_SubmitFrame(hmd, 0, nullptr, &layers, 1);
#endif
	}
#endif
}

void VR_DrawTimewarpFrame()
{
#ifdef OVR_MAJOR_VERSION
#if OVR_MAJOR_VERSION <= 5
	if (g_has_rift)
	{
		ovrFrameTiming frameTime = ovrHmd_BeginFrame(hmd, ++g_ovr_frameindex);
		//const ovrTexture* new_eye_texture = new ovrTexture(FramebufferManager::m_eye_texture[0].Texture);
		//ovrD3D11Texture new_eye_texture;
		//memcpy((void*)&new_eye_texture, &FramebufferManager::m_eye_texture[0], sizeof(ovrD3D11Texture));

		//ovrPosef new_eye_poses[2];
		//memcpy((void*)&new_eye_poses, g_eye_poses, sizeof(ovrPosef)*2);

		ovr_WaitTillTime(frameTime.NextFrameSeconds - g_ActiveConfig.fTimeWarpTweak);

		ovrHmd_EndFrame(hmd, g_eye_poses, &g_eye_texture[0].Texture);
	}
#endif
#endif
}

}