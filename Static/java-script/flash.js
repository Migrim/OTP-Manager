document.addEventListener('DOMContentLoaded', function() {
    function fetchFlashMessages() {
        fetch('/get_flash_messages')
            .then(response => response.json())
            .then(data => {
                if (data && data.length > 0) {
                    const container = document.getElementById('flash-messages-container');
                    container.innerHTML = '';  // Clear old messages
                    data.forEach(({category, message}) => {
                        const div = document.createElement('div');
                        div.className = `flash-message flash-${category}`;
                        div.innerHTML = `
                            <span class="material-icons-outlined flash-icon">${category}</span>
                            ${message}
                            <span class="flash-close-btn">&times;</span>
                        `;
                        container.appendChild(div);

                        // Set up close button for each message
                        div.querySelector('.flash-close-btn').onclick = function() {
                            var flashMessage = this.parentElement;
                            flashMessage.style.animation = 'fadeOutSlideDown 0.5s ease forwards';  // Fade out animation
                            setTimeout(function() { flashMessage.remove(); }, 500);
                        };

                        // Automatically remove flash messages after 5 seconds
                        setTimeout(() => {
                            div.style.animation = 'fadeOutSlideDown 0.5s ease forwards';  // Fade out animation
                            setTimeout(() => { div.remove(); }, 500); 
                        }, 5000);
                    });
                }
            })
            .catch(error => console.error('Error fetching flash messages:', error));
    }

    // Fetch flash messages every second
    setInterval(fetchFlashMessages, 1000);

    // Trigger flash messages fetching immediately
    fetchFlashMessages();
});
