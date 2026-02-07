# Web UI for QRNG Entropy Demos

A beautiful, presentation-ready web interface for demonstrating QRNG entropy demos in webinars and presentations.

## Features

- 🎨 **Modern, Professional UI** - Clean design perfect for presentations
- 📊 **Interactive Demos** - Three different entropy demonstrations
- ⚡ **Real-time Updates** - Live progress tracking during brute-force attacks
- 📱 **Responsive Design** - Works on different screen sizes
- 🎯 **Easy to Use** - Simple interface for live demonstrations

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Running the Web Application

1. Start the Flask server:
```bash
python3 web_demo_app.py
```

2. Open your web browser and navigate to the URL shown in the terminal (typically `http://localhost:5001`)

   Note: The app automatically uses port 5001 to avoid conflicts with macOS AirPlay Receiver on port 5000.

3. For remote access (e.g., if presenting from a different machine):
   - The server will show the port number when it starts
   - Access from other machines using: `http://YOUR_IP_ADDRESS:PORT`

## Available Demos

### 1. Entropy Effectiveness Demo
- Compares weak timestamp-based entropy vs. QRNG entropy
- Performs live brute-force attack on weak seeds
- Shows work factor comparisons
- Displays attack results in real-time

### 2. RSA Shared Prime Demo
- Generates RSA keys with weak vs. QRNG entropy
- Scans for shared prime factors
- Shows vulnerability statistics
- Demonstrates security impact of entropy quality

### 3. QRNG Key Derivation Demo
- Simple demonstration of key derivation from QRNG
- Shows encryption process
- Explains why brute-force fails with high entropy

## Usage Tips for Presentations

1. **Prepare QRNG Data**: Have your base64-encoded QRNG data ready to paste
2. **Test First**: Run through each demo before the presentation
3. **Full Screen**: Use browser full-screen mode (F11) for cleaner presentation
4. **Window Size**: Adjust brute-force window based on demo timing needs
5. **Clear Results**: Use "Clear Results" button between demonstrations

## QRNG Data Format

- Base64-encoded binary data
- At least 256 bytes of raw QRNG data (2048 bits)
- Paste directly into the text area in the UI

## Example QRNG Data Generation (for testing)

```bash
# Generate test data (NOT real QRNG - for testing only!)
python3 -c "import base64, os; print(base64.b64encode(os.urandom(256)).decode())"
```

## Troubleshooting

### Port Already in Use
The app automatically finds an available port starting from 5001 (to avoid macOS AirPlay Receiver on port 5000). If you need a specific port, modify the `find_free_port()` call in `web_demo_app.py`.

### Import Errors
Make sure all dependencies are installed:
```bash
pip install -r requirements.txt
```

### QRNG Data Errors
- Ensure data is valid base64
- Check that decoded data is at least 256 bytes
- Remove any whitespace or newlines if needed

## Architecture

- **Backend**: Flask (Python) - `web_demo_app.py`
- **Frontend**: HTML/CSS/JavaScript - `templates/index.html`
- **API Endpoints**:
  - `/api/entropy-demo` - Entropy effectiveness comparison
  - `/api/rsa-demo` - RSA shared prime detection
  - `/api/qrng-simple` - Simple QRNG key derivation

## Security Notes

⚠️ This is a demonstration application for educational purposes:
- Not intended for production use
- Uses demo-sized RSA keys (512 bits) - NOT secure
- Brute-force attacks are constrained for safety
- All demos are designed for presentation purposes

## Browser Compatibility

- Chrome/Edge (recommended)
- Firefox
- Safari
- Modern browsers with JavaScript enabled

## Presentation Tips

1. **Start with Entropy Effectiveness Demo** - Most visual and engaging
2. **Show Weak Case First** - Demonstrates the problem clearly
3. **Then Show QRNG Case** - Highlights the solution
4. **Use RSA Demo** - For deeper technical audience
5. **Keep QRNG Data Ready** - Have it copied to clipboard

Enjoy your presentation! 🎤
