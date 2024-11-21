        // Handle form submission with client-side validation
        document.getElementById('resetPasswordForm').addEventListener('submit', async function (event) {
            event.preventDefault();

            const token = document.getElementById('token').value;
            const newPassword = document.getElementById('newPassword').value;

            // Basic password validation (optional)
            if (newPassword.length < 8) {
                alert('Password must be at least 8 characters long.');
                return;
            }

            try {
                const response = await fetch('/reset-password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ token, newPassword })
                });

                const result = await response.text();

                if (response.ok) {
                    alert(result.message);  // Show success message in alert
                    window.location.href = '/login.html';  // Redirect to login page after success
                } else {
                    alert(result.message);  // Show error message in alert
                }
            } catch (error) {
                alert('An error occurred while resetting the password. Please try again.');
            }
        });
