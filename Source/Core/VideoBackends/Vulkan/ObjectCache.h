// Copyright 2015 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#pragma once

#include <array>
#include <cstring>
#include <map>
#include <memory>
#include <vector>

#include "VideoCommon/GeometryShaderGen.h"
#include "VideoCommon/PixelShaderGen.h"
#include "VideoCommon/VertexShaderGen.h"
#include "VideoCommon/VideoCommon.h"

#include "VideoBackends/Vulkan/Globals.h"
#include "VideoBackends/Vulkan/VulkanImports.h"
#include "VideoBackends/Vulkan/ShaderCache.h"
#include "VideoBackends/Vulkan/StaticShaderCache.h"

namespace Vulkan {

class CommandBufferManager;
class VertexFormat;
class StreamBuffer;

// Game shader state encompassed by pipelines
struct PipelineInfo
{
	const VertexFormat* vertex_format;
	VkShaderModule vs;
	VkShaderModule gs;
	VkShaderModule ps;
	VkRenderPass render_pass;
	RasterizationState rasterization_state;
	DepthStencilState depth_stencil_state;
	BlendState blend_state;
	VkPrimitiveTopology primitive_topology;
};

bool operator==(const PipelineInfo& lhs, const PipelineInfo& rhs);
bool operator!=(const PipelineInfo& lhs, const PipelineInfo& rhs);
bool operator<(const PipelineInfo& lhs, const PipelineInfo& rhs);
bool operator>(const PipelineInfo& lhs, const PipelineInfo& rhs);

class ObjectCache
{
public:
	ObjectCache(VkInstance instance, VkPhysicalDevice physical_device, VkDevice device, CommandBufferManager* command_buffer_mgr, const SupportBits& features);
	~ObjectCache();

	VkInstance GetVulkanInstance() const { return m_instance; }
	VkPhysicalDevice GetPhysicalDevice() const { return m_physical_device; }
	VkDevice GetDevice() const { return m_device; }

	CommandBufferManager* GetCommandBufferManager() const { return m_command_buffer_mgr; }

	const VkPhysicalDeviceMemoryProperties& GetDeviceMemoryProperties() const { return m_device_memory_properties; }

	// Support bits
	bool SupportsGeometryShaders() const { return m_support_bits.SupportsGeometryShaders; }
	bool SupportsDualSourceBlend() const { return m_support_bits.SupportsDualSourceBlend; }

	VkDescriptorSetLayout GetDescriptorSetLayout(DESCRIPTOR_SET set) const { return m_descriptor_set_layouts[set]; }
	VkPipelineLayout GetPipelineLayout() const { return m_pipeline_layout; }
	VertexFormat* GetBackendShaderVertexFormat() const { return m_backend_shader_vertex_format.get(); }
	StreamBuffer* GetBackendShaderVertexBuffer() const { return m_backend_shader_vertex_buffer.get(); }
	StreamBuffer* GetBackendShaderUniformBuffer() const { return m_backend_shader_uniform_buffer.get(); }

	// Accesses shader module caches
	VertexShaderCache& GetVertexShaderCache() { return m_vs_cache; }
	GeometryShaderCache& GetGeometryShaderCache() { return m_gs_cache; }
	PixelShaderCache& GetPixelShaderCache() { return m_ps_cache; }
	StaticShaderCache& GetStaticShaderCache() { return m_static_shader_cache; }

	// Perform at startup, create descriptor layouts, compiles all static shaders.
	bool Initialize();

	// Finds a memory type index for the specified memory properties and the bits returned by vkGetImageMemoryRequirements
	u32 GetMemoryType(u32 bits, VkMemoryPropertyFlags desired_properties);

	// Find a pipeline by the specified description, if not found, attempts to create it
	VkPipeline GetPipeline(const PipelineInfo& info);

	// Wipes out the pipeline cache, use when MSAA modes change, for example
	void ClearPipelineCache();

	// Recompile static shaders, call when MSAA mode changes, etc.
	// Destroys the old shader modules, so assumes that the pipeline cache is clear first.
	bool RecompileStaticShaders();

private:
	bool CreateDescriptorSetLayouts();
	bool CreatePipelineLayout();
	bool CreateBackendShaderVertexFormat();

	VkInstance m_instance = VK_NULL_HANDLE;
	VkPhysicalDevice m_physical_device = VK_NULL_HANDLE;
	VkDevice m_device = VK_NULL_HANDLE;

	CommandBufferManager* m_command_buffer_mgr = nullptr;

	VkPhysicalDeviceMemoryProperties m_device_memory_properties = {};

	SupportBits m_support_bits;

	std::array<VkDescriptorSetLayout, NUM_DESCRIPTOR_SETS> m_descriptor_set_layouts = {};

	VkPipelineLayout m_pipeline_layout = VK_NULL_HANDLE;

	std::unique_ptr<VertexFormat> m_backend_shader_vertex_format;
	std::unique_ptr<StreamBuffer> m_backend_shader_vertex_buffer;
	std::unique_ptr<StreamBuffer> m_backend_shader_uniform_buffer;

	VertexShaderCache m_vs_cache;
	GeometryShaderCache m_gs_cache;
	PixelShaderCache m_ps_cache;

	StaticShaderCache m_static_shader_cache;

	// TODO: Replace with hash table
	std::map<PipelineInfo, VkPipeline> m_pipeline_cache;
};

}  // namespace Vulkan
