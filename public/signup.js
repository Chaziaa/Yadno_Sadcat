document.getElementById('signupForm').addEventListener('submit', async function(event) {
    event.preventDefault();

    document.getElementById('passwordError').textContent = ''; // Clear previous messages

    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value.trim();
    const confirmPassword = document.getElementById('confirmPassword').value.trim();

    let hasError = false;

    const passwordPattern = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
    let errorMessage = "";

    // Check if email is valid
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(email)) {
        errorMessage = "Please enter a valid email address.";
        hasError = true;
    }

    // Check if password meets complexity requirements
    if (!passwordPattern.test(password)) {
        errorMessage = "Password must be at least 8 characters long, contain at least one uppercase letter, one number, and one special character.";
        hasError = true;
    }

    // Check if passwords match
    if (password !== confirmPassword) {
        errorMessage = "Passwords do not match.";
        hasError = true;
    }

    if (hasError) {
        document.getElementById('passwordError').textContent = errorMessage;
        return;
    }

    try {
        console.log('Submitting form...');
        const response = await fetch('/signup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });

        console.log('Response received:', response);

        if (!response.ok) {
            const errorData = await response.json();
            console.log('HTTP error, status = ' + response.status);
            document.getElementById('passwordError').textContent = errorData.message || `HTTP error: ${response.status}`;
            return;
        }

        const data = await response.json();
        console.log('Data received:', data);

        if (data.success) {
            console.log('Redirecting to login page...'); // Debugging message
            window.location.href = 'login.html'; // Redirect if signup successful
        } else {
            document.getElementById('passwordError').textContent = data.message;
        }
    } catch (error) {
        console.error('Error:', error);
        document.getElementById('passwordError').textContent = 'An unexpected error occurred. Please try again later.';
    }  
});
