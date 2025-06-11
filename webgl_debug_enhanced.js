// Enhanced WebGL Debug Script
// Run this in the browser console to get detailed WebGL information

console.log("=== WebGL Debug Information ===");

// 1. Check WebGL Support
const canvas = document.createElement('canvas');
const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
const gl2 = canvas.getContext('webgl2');

console.log("WebGL 1 Support:", gl ? "YES" : "NO");
console.log("WebGL 2 Support:", gl2 ? "YES" : "NO");

if (gl) {
    // 2. Get WebGL Context Information
    console.log("\n=== WebGL Context Info ===");
    console.log("Vendor:", gl.getParameter(gl.VENDOR));
    console.log("Renderer:", gl.getParameter(gl.RENDERER));
    console.log("WebGL Version:", gl.getParameter(gl.VERSION));
    console.log("GLSL Version:", gl.getParameter(gl.SHADING_LANGUAGE_VERSION));
    
    // 3. Check Context Limits
    console.log("\n=== WebGL Limits ===");
    console.log("Max Texture Size:", gl.getParameter(gl.MAX_TEXTURE_SIZE));
    console.log("Max Cube Map Size:", gl.getParameter(gl.MAX_CUBE_MAP_TEXTURE_SIZE));
    console.log("Max Render Buffer Size:", gl.getParameter(gl.MAX_RENDERBUFFER_SIZE));
    console.log("Max Viewport Dims:", gl.getParameter(gl.MAX_VIEWPORT_DIMS));
    console.log("Max Vertex Attributes:", gl.getParameter(gl.MAX_VERTEX_ATTRIBS));
    console.log("Max Texture Image Units:", gl.getParameter(gl.MAX_TEXTURE_IMAGE_UNITS));
    
    // 4. Check for WebGL Errors
    const error = gl.getError();
    console.log("\n=== WebGL Error State ===");
    console.log("Current Error:", error === gl.NO_ERROR ? "None" : error);
}

// 5. Check existing WebGL contexts
console.log("\n=== Active WebGL Contexts ===");
const allCanvases = document.querySelectorAll('canvas');
console.log("Total canvas elements:", allCanvases.length);
allCanvases.forEach((canvas, index) => {
    console.log(`Canvas ${index}:`, {
        width: canvas.width,
        height: canvas.height,
        hasWebGL: canvas.getContext ? "possible" : "no",
        parent: canvas.parentElement?.id || canvas.parentElement?.className || "unknown"
    });
});

// 6. Check Three.js specific
console.log("\n=== Three.js Status ===");
console.log("THREE object exists:", typeof THREE !== 'undefined');
if (typeof THREE !== 'undefined') {
    console.log("THREE.REVISION:", THREE.REVISION);
    console.log("THREE.WebGLRenderer exists:", typeof THREE.WebGLRenderer !== 'undefined');
}

// 7. Browser Info
console.log("\n=== Browser Info ===");
console.log("User Agent:", navigator.userAgent);
console.log("Platform:", navigator.platform);
console.log("Hardware Concurrency:", navigator.hardwareConcurrency);
console.log("Device Memory:", navigator.deviceMemory ? navigator.deviceMemory + "GB" : "unknown");

// 8. GPU Info (if available)
if (gl) {
    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    if (debugInfo) {
        console.log("\n=== GPU Info ===");
        console.log("GPU Vendor:", gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL));
        console.log("GPU Renderer:", gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL));
    }
}

// 9. Check for WebGL context loss
console.log("\n=== Context Loss Prevention ===");
if (gl) {
    const loseContext = gl.getExtension('WEBGL_lose_context');
    console.log("WEBGL_lose_context extension:", loseContext ? "available" : "not available");
}

// 10. Try creating a test Three.js renderer
console.log("\n=== Three.js Test ===");
if (typeof THREE !== 'undefined') {
    try {
        const testCanvas = document.createElement('canvas');
        testCanvas.width = 100;
        testCanvas.height = 100;
        
        const testRenderer = new THREE.WebGLRenderer({ 
            canvas: testCanvas,
            antialias: false,
            alpha: true,
            powerPreference: "default"
        });
        
        console.log("✅ Test renderer created successfully");
        testRenderer.dispose();
        console.log("✅ Test renderer disposed successfully");
    } catch (error) {
        console.error("❌ Test renderer failed:", error);
    }
}

console.log("\n=== End Debug Info ===");