// API base URL
const API_BASE = '/api';

// Get link code
async function getLinkCode() {
    const phoneInput = document.getElementById('phone');
    const output = document.getElementById('output');
    const phone = phoneInput.value.trim();

    if (!phone || phone.length !== 12) {
        showOutput(output, 'Please enter a valid 12-digit phone number (254...)', 'error');
        return;
    }

    showOutput(output, 'Generating link code...', 'loading');

    try {
        const response = await fetch(`${API_BASE}/get-link-code?phone=${phone}`);
        const data = await response.json();

        if (data.success) {
            const linkCode = data.code;
            output.innerHTML = `
                <div class="success">
                    <h3>✅ Link Code Generated!</h3>
                    <p>Your WhatsApp Link Code:</p>
                    <div style="font-size: 2em; font-weight: bold; text-align: center; margin: 15px 0; color: #667eea;">
                        ${linkCode}
                    </div>
                    <p><strong>Follow these steps:</strong></p>
                    <ol style="text-align: left; margin: 15px 0;">
                        <li>Open WhatsApp on your phone</li>
                        <li>Send this exact message to <strong>BeraPay</strong>:</li>
                        <li style="margin: 10px 0;">
                            <code style="background: #333; color: white; padding: 8px 12px; border-radius: 5px; font-size: 1.1em;">
                                .link ${linkCode}
                            </code>
                        </li>
                        <li>Wait for confirmation message</li>
                        <li>Then type <code>.menu</code> to access your wallet</li>
                    </ol>
                    <p><small>Code expires in 10 minutes</small></p>
                </div>
            `;
        } else {
            showOutput(output, data.message, 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showOutput(output, 'Failed to generate link code. Please try again.', 'error');
    }
}

// Show registration modal
function showRegister() {
    document.getElementById('registerModal').style.display = 'block';
}

// Close registration modal
function closeRegister() {
    document.getElementById('registerModal').style.display = 'none';
}

// Register new user
async function registerUser() {
    const name = document.getElementById('regName').value.trim();
    const phone = document.getElementById('regPhone').value.trim();
    const pin = document.getElementById('regPin').value.trim();
    const output = document.getElementById('registerOutput');

    if (!name || !phone || !pin) {
        showOutput(output, 'Please fill all fields', 'error');
        return;
    }

    if (phone.length !== 12) {
        showOutput(output, 'Please enter valid 12-digit phone number', 'error');
        return;
    }

    if (pin.length !== 4 || !/^\d+$/.test(pin)) {
        showOutput(output, 'PIN must be 4 digits', 'error');
        return;
    }

    showOutput(output, 'Creating your wallet...', 'loading');

    try {
        const response = await fetch(`${API_BASE}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ name, phone, pin })
        });

        const data = await response.json();

        if (data.success) {
            showOutput(output, `
                ✅ Registration Successful!
                <p>Wallet ID: <strong>${data.walletId}</strong></p>
                <p>Now generate your link code to connect WhatsApp.</p>
            `, 'success');
            
            // Clear form
            document.getElementById('regName').value = '';
            document.getElementById('regPhone').value = '';
            document.getElementById('regPin').value = '';
            
            // Close modal after 3 seconds
            setTimeout(() => {
                closeRegister();
            }, 3000);
        } else {
            showOutput(output, data.message, 'error');
        }
    } catch (error) {
        console.error('Registration error:', error);
        showOutput(output, 'Registration failed. Please try again.', 'error');
    }
}

// Utility function to show output
function showOutput(element, message, type = '') {
    element.innerHTML = `<div class="${type}">${message}</div>`;
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('registerModal');
    if (event.target === modal) {
        closeRegister();
    }
}

// Add input validation
document.addEventListener('DOMContentLoaded', function() {
    const phoneInputs = document.querySelectorAll('input[type="tel"]');
    
    phoneInputs.forEach(input => {
        input.addEventListener('input', function(e) {
            e.target.value = e.target.value.replace(/\D/g, '');
        });
    });

    const pinInputs = document.querySelectorAll('input[type="password"][maxlength="4"]');
    
    pinInputs.forEach(input => {
        input.addEventListener('input', function(e) {
            e.target.value = e.target.value.replace(/\D/g, '').slice(0, 4);
        });
    });
});
