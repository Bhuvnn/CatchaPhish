function showLoading() {
    document.getElementById("loading-screen").style.display = "flex";
}

function hideLoading() {
    document.getElementById("loading-screen").style.display = "none";
}

function showPopup(message) {
    let popup = document.getElementById('popup');
    popup.innerText = message;
    popup.classList.add('show'); // Show popup

    setTimeout(() => {
        popup.classList.remove('show'); // Hide smoothly after 5 seconds
    }, 5000);
}

document.getElementById('scanForm').addEventListener('submit', async function(event) {
    event.preventDefault(); // Prevent page refresh

    let formData = new FormData(this);
    let resultDiv = document.getElementById("result");

    showLoading(); // Show loading screen

    try {
        let response = await fetch('/scan_URL', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error("Network response was not ok");
        }

        let data = await response.json(); // Wait for model's response

        hideLoading(); // Ensure loading screen is hidden once response is received

        if (data.message) {
            showPopup(data.message); // Show popup with result
            resultDiv.innerHTML = `<p><strong>Prediction:</strong> ${data.message}</p>`;
        } else {
            console.error("No message received:", data);
        }
    } catch (error) {
        console.error('Fetch error:', error);
        resultDiv.innerHTML = `<p style="color: red;">Error processing request.</p>`;
        hideLoading(); // Ensure loading screen hides even if there is an error
    }
});


document.addEventListener("DOMContentLoaded", function() {
    document.getElementById("scanForm").addEventListener("submit", function(event) {
        event.preventDefault();  // Prevent form refresh

        fetch('/scan_URL', {
            method: 'POST',
            body: new FormData(this)  // Send form data to Flask
        })
        .then(response => response.json())  // Parse JSON response
        .then(data => {
            const popup = document.querySelector('.popup');

            if (!popup) {
                console.error("Popup element not found!");
                return;
            }

            popup.textContent = data.message;  // Keep the Flask response message

            // Remove previous color classes
            popup.classList.remove('safe', 'phishing');

            // Change background color based on phishing detection
            if (data.phishing) {
                popup.classList.add('phishing');  // Add red color class
                console.log("Popup color changed to RED (Phishing)");
            } else {
                popup.classList.add('safe');  // Add green color class
                console.log("Popup color changed to GREEN (Safe)");
            }

            console.log("Popup classes:", popup.classList);

            // Show the popup
            popup.classList.add('show');

            // Hide after 3 seconds
            setTimeout(() => {
                popup.classList.remove('show');
            }, 3000);
        })
        .catch(error => console.error("Error:", error));
    });
});




