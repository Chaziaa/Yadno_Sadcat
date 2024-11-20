document.getElementById('forgotPasswordForm').addEventListener('submit', async function(event) {
    event.preventDefault();

    const email = document.getElementById('email').value;
    if (!validateEmail(email)) {
        alert('Please enter a valid email address.');
        return;
    }

    try {
        const response = await fetch('/forgot-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email }),
            credentials: 'include', // Ensure credentials are included if necessary
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Error processing request.');
        }

        alert('Password reset token sent to ' + email + '. Please check your inbox.');
        window.location.href = '/reset-password.html';
    } catch (error) {
        console.error('Error processing request:', error);
        alert('Error: ' + error.message);
    }
});

function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).toLowerCase());
}
