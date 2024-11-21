// Fetch user data to populate the dashboard
        window.onload = function () {
            fetch('/dashboard-data', { credentials: 'include' })
                .then((response) => response.json())
                .then((data) => {
                    document.getElementById('userName').innerText = data.name;
                })
                .catch((error) => console.error('Error fetching user data:', error));
        };

        // Logout functionality
        function logout() {
            fetch('/logout', {
                method: 'POST',
                credentials: 'include'
            })
            .then(response => {
                if (response.ok) {
                    window.location.href = '/login.html';
                }
            })
            .catch(error => console.error('Logout error:', error));
        }
