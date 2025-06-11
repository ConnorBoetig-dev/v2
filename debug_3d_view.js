// Debug script for 3D view issues
// Add this to the console to debug

// Check if THREE is loaded
console.log("THREE loaded:", typeof THREE !== 'undefined');

// Check if OrbitControls is available
console.log("OrbitControls on THREE:", typeof THREE.OrbitControls !== 'undefined');

// Check 3D container
const container3d = document.getElementById('network-3d');
console.log("3D container found:", container3d !== null);
console.log("3D container display:", container3d ? container3d.style.display : 'N/A');
console.log("3D container dimensions:", container3d ? {
    width: container3d.clientWidth,
    height: container3d.clientHeight,
    offsetWidth: container3d.offsetWidth,
    offsetHeight: container3d.offsetHeight
} : 'N/A');

// Check if visualization3D exists
console.log("visualization3D exists:", typeof visualization3D !== 'undefined');

// Try to manually show 3D view
if (container3d) {
    container3d.style.display = 'block';
    container3d.style.width = '100%';
    container3d.style.height = '600px'; // Force a height
    console.log("Forced 3D container to display");
}

// Check if we can create a simple 3D scene
if (typeof THREE !== 'undefined') {
    try {
        const testScene = new THREE.Scene();
        const testCamera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        const testRenderer = new THREE.WebGLRenderer();
        console.log("✓ Can create THREE.js objects");
        
        // Test OrbitControls
        if (typeof THREE.OrbitControls !== 'undefined') {
            const testControls = new THREE.OrbitControls(testCamera, testRenderer.domElement);
            console.log("✓ Can create OrbitControls");
        } else {
            console.log("✗ OrbitControls not available on THREE object");
        }
    } catch (e) {
        console.error("Error creating THREE.js objects:", e);
    }
}

// Force initialize 3D view
if (typeof initialize3DVisualization === 'function' && !visualization3D) {
    console.log("Forcing 3D initialization...");
    initialize3DVisualization();
}