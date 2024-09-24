// Select elements
const certificateInput = document.getElementById('certificate');
const sendButton = document.getElementById('send-button');
const form = document.getElementById('certificate-form');
const preview = document.getElementById('certificate-preview');
const fontPreview = document.getElementById('fontPreview');

// Disable the send button initially
sendButton.disabled = true;

// Enable the send button only if all fields are filled
form.addEventListener('input', () => {
    const excel = document.getElementById('excel').files.length > 0;
    const certificate = document.getElementById('certificate').files.length > 0;
    const font = document.getElementById('font').value;
    const size = document.getElementById('fontsize').value;
    const greeting = document.getElementById('greeting').value;
    const body = document.getElementById('body').value;

    // Enable send button if all fields are filled
    if (excel && certificate && font && size && greeting && body) {
        sendButton.disabled = false;
    } else {
        sendButton.disabled = true;
    }
});

// Preview the certificate when a file is selected
certificateInput.addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (file) {
        const reader = new FileReader();

        reader.onload = function(e) {
            const img = document.createElement('img');
            img.src = e.target.result;
            img.style.maxWidth = '100%';
            preview.innerHTML = '';
            preview.appendChild(img);
            preview.style.display = 'block';
        };

        reader.readAsDataURL(file);
    }
});

// Preview font change
function updateFontPreview() {
    var font = document.getElementById('font').value;
    var size = document.getElementById('fontsize').value;
    var preview = document.getElementById('fontPreview');
    preview.style.fontFamily = font;
    preview.style.fontSize = size + 'px';
    preview.textContent = 'Sample Text';  // Update with sample text to preview
}


// Alert the user when the form is submitted
form.addEventListener('submit', (event) => {
    event.preventDefault();  // Prevent the default form submission behavior

    // Display a loading message or animation
    sendButton.textContent = 'Sending...';
    sendButton.disabled = true;

    // Simulate a delay (optional) for user experience
    setTimeout(() => {
        // You can implement the actual form submission logic here
        alert('Certificates sent successfully!');
        sendButton.textContent = 'Send Certificates';
        sendButton.disabled = false;

        // Reset the form
        form.reset();
        preview.style.display = 'none';
        fontPreview.textContent = 'Sample Text';  // Reset preview text
    }, 2000);
});

document.addEventListener('DOMContentLoaded', function() {
    // Fetch font list from the server
    fetch('/api/font-list')
    .then(response => response.json())
    .then(fonts => {
        const fontSelect = document.getElementById('font');
        fonts.forEach(font => {
            const option = document.createElement('option');
            option.value = font;
            option.textContent = font;
            fontSelect.appendChild(option);
        });
    })
    .catch(error => console.error('Error loading fonts:', error));
});


window.onload = function() {
    updateFontPreview();
};
