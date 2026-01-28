/**
 * FTC Node Icon Generator
 * Creates Bitcoin-style ICO file with "F" letter
 *
 * Usage: node generate-ico.js
 * Requirements: npm install canvas png-to-ico
 */

const { createCanvas } = require('canvas');
const fs = require('fs');
const path = require('path');

// png-to-ico may export default or as a function
let pngToIco;
try {
    const mod = require('png-to-ico');
    pngToIco = mod.default || mod;
} catch (e) {
    pngToIco = null;
}

function drawIcon(ctx, size) {
    const scale = size / 512;
    ctx.save();
    ctx.scale(scale, scale);

    // Background circle with gradient
    const gradient = ctx.createLinearGradient(0, 0, 512, 512);
    gradient.addColorStop(0, '#F7931A');
    gradient.addColorStop(1, '#E8820A');

    ctx.beginPath();
    ctx.arc(256, 256, 240, 0, Math.PI * 2);
    ctx.fillStyle = gradient;
    ctx.fill();

    // Inner subtle ring
    ctx.beginPath();
    ctx.arc(256, 256, 220, 0, Math.PI * 2);
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.15)';
    ctx.lineWidth = 3;
    ctx.stroke();

    // Rotate for Bitcoin-style tilt
    ctx.translate(256, 256);
    ctx.rotate(-12 * Math.PI / 180);
    ctx.translate(-256, -256);

    // Draw F symbol
    ctx.fillStyle = '#FFFFFF';

    // Helper function for rounded rectangles
    function roundRect(x, y, width, height, radius) {
        ctx.beginPath();
        ctx.moveTo(x + radius, y);
        ctx.lineTo(x + width - radius, y);
        ctx.quadraticCurveTo(x + width, y, x + width, y + radius);
        ctx.lineTo(x + width, y + height - radius);
        ctx.quadraticCurveTo(x + width, y + height, x + width - radius, y + height);
        ctx.lineTo(x + radius, y + height);
        ctx.quadraticCurveTo(x, y + height, x, y + height - radius);
        ctx.lineTo(x, y + radius);
        ctx.quadraticCurveTo(x, y, x + radius, y);
        ctx.closePath();
    }

    // Main vertical bar of F
    roundRect(175, 115, 52, 285, 26);
    ctx.fill();

    // Top horizontal bar of F
    roundRect(175, 115, 165, 52, 26);
    ctx.fill();

    // Middle horizontal bar of F
    roundRect(175, 225, 130, 48, 24);
    ctx.fill();

    // Top serif extension (Bitcoin-style)
    roundRect(295, 70, 38, 80, 19);
    ctx.fill();

    // Bottom serif extension (Bitcoin-style)
    roundRect(193, 365, 38, 80, 19);
    ctx.fill();

    ctx.restore();
}

// Create ICO manually using raw format
function createIcoManually(outputDir, sizes) {
    console.log('\nCreating ICO file manually...');

    const pngBuffers = sizes.map(size => {
        const pngPath = path.join(outputDir, `ftc-node-${size}.png`);
        return { size, data: fs.readFileSync(pngPath) };
    });

    // ICO header: 6 bytes
    // ICONDIR structure
    const headerSize = 6;
    const entrySize = 16; // ICONDIRENTRY size
    const numImages = pngBuffers.length;

    let offset = headerSize + (entrySize * numImages);
    const entries = [];
    const imageData = [];

    for (const { size, data } of pngBuffers) {
        entries.push({
            width: size >= 256 ? 0 : size,  // 0 means 256
            height: size >= 256 ? 0 : size,
            colorCount: 0,
            reserved: 0,
            planes: 1,
            bitCount: 32,
            bytesInRes: data.length,
            imageOffset: offset
        });
        imageData.push(data);
        offset += data.length;
    }

    // Build ICO file
    const totalSize = offset;
    const ico = Buffer.alloc(totalSize);
    let pos = 0;

    // ICONDIR header
    ico.writeUInt16LE(0, pos); pos += 2;      // Reserved
    ico.writeUInt16LE(1, pos); pos += 2;      // Type (1 = ICO)
    ico.writeUInt16LE(numImages, pos); pos += 2; // Number of images

    // ICONDIRENTRY for each image
    for (const entry of entries) {
        ico.writeUInt8(entry.width, pos); pos += 1;
        ico.writeUInt8(entry.height, pos); pos += 1;
        ico.writeUInt8(entry.colorCount, pos); pos += 1;
        ico.writeUInt8(entry.reserved, pos); pos += 1;
        ico.writeUInt16LE(entry.planes, pos); pos += 2;
        ico.writeUInt16LE(entry.bitCount, pos); pos += 2;
        ico.writeUInt32LE(entry.bytesInRes, pos); pos += 4;
        ico.writeUInt32LE(entry.imageOffset, pos); pos += 4;
    }

    // Image data (PNG format)
    for (const data of imageData) {
        data.copy(ico, pos);
        pos += data.length;
    }

    const icoPath = path.join(outputDir, 'ftc-node.ico');
    fs.writeFileSync(icoPath, ico);
    console.log(`  Created: ftc-node.ico (${sizes.join(', ')}px sizes)`);
    console.log('\nDone! Icon files created successfully.');
}

async function generateIcon() {
    const sizes = [256, 128, 64, 48, 32, 16];
    const pngBuffers = [];
    const outputDir = __dirname;

    console.log('Generating FTC Node icon (Bitcoin-style with F)...\n');

    for (const size of sizes) {
        const canvas = createCanvas(size, size);
        const ctx = canvas.getContext('2d');

        // Clear with transparency
        ctx.clearRect(0, 0, size, size);

        drawIcon(ctx, size);

        const buffer = canvas.toBuffer('image/png');
        pngBuffers.push(buffer);

        // Also save individual PNGs
        const pngPath = path.join(outputDir, `ftc-node-${size}.png`);
        fs.writeFileSync(pngPath, buffer);
        console.log(`  Created: ftc-node-${size}.png`);
    }

    // Create ICO file
    if (pngToIco && typeof pngToIco === 'function') {
        try {
            // Pass file paths instead of buffers
            const pngPaths = sizes.map(s => path.join(outputDir, `ftc-node-${s}.png`));
            const icoBuffer = await pngToIco(pngPaths);
            const icoPath = path.join(outputDir, 'ftc-node.ico');
            fs.writeFileSync(icoPath, icoBuffer);
            console.log(`\n  Created: ftc-node.ico (${sizes.join(', ')}px sizes)`);
            console.log('\nDone! Icon files created successfully.');
        } catch (err) {
            console.error('Error creating ICO:', err.message);
            createIcoManually(outputDir, sizes);
        }
    } else {
        createIcoManually(outputDir, sizes);
    }
}

generateIcon().catch(err => {
    console.error('Error:', err.message);
    console.log('\nTo install dependencies, run:');
    console.log('  npm install canvas png-to-ico');
});
