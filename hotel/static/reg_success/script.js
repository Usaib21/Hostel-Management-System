// script.js

// Code for your custom confirmation popup
document.addEventListener('DOMContentLoaded', function () {
    const cancelHostelButton = document.getElementById('cancelHostelButton');
    const confirmationPopup = document.getElementById('customConfirmationPopup');
    const confirmCancelHostelButton = document.getElementById('confirmCancelHostel');
    const cancelCancelHostelButton = document.getElementById('cancelCancelHostel');

    cancelHostelButton.addEventListener('click', function () {
        confirmationPopup.style.display = 'flex';
    });

    confirmCancelHostelButton.addEventListener('click', function () {
        // Add logic to cancel hostel and remove student details here
        // Redirect to a confirmation page after successful cancellation
        // Replace 'home' with the actual URL name for the home page
        window.location.href = "{% url 'home' %}";
    });

    cancelCancelHostelButton.addEventListener('click', function () {
        confirmationPopup.style.display = 'none';
    });
});

// Other JavaScript code for addressButtons and other functionality
// ...
