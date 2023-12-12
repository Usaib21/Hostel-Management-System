document.addEventListener('DOMContentLoaded', function () {
    const changeRoomLinks = document.querySelectorAll('.change-room-link');
    const confirmationPopup = document.getElementById('customConfirmationPopup');
    const confirmChangeButton = document.getElementById('confirmChange');
    const cancelChangeButton = document.getElementById('cancelChange');
    const newRoomInput = document.getElementById('new_room_input');
  
    changeRoomLinks.forEach(function (link) {
      link.addEventListener('click', function (event) {
        event.preventDefault();
        const roomId = this.getAttribute('data-room-id');
        newRoomInput.value = roomId;
        confirmationPopup.style.display = 'flex';
      });
    });
  
    confirmChangeButton.addEventListener('click', function () {
      const roomId = newRoomInput.value;
      confirmationPopup.style.display = 'none';
      if (roomId) {
        // Perform an AJAX request to change the room
        fetch(`/change_room/?new_room=${roomId}`, { method: 'POST' })
          .then(response => response.json())
          .then(data => {
            // Handle the response data here
            console.log(data);
            // Reload the page or show a success message
          })
          .catch(error => {
            console.error('Error:', error);
            // Handle the error here
          });
      }
    });
  
    cancelChangeButton.addEventListener('click', function () {
      confirmationPopup.style.display = 'none';
    });
  });
  