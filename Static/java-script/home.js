const countdownIntervals = new Map();
const emojiList = [
    '😇', '🧐', '🫠', '🚫', '💀', '✨', '🥺', 
    '🔥', '🌈', '😂', 
    '👽', '👾', '🎃', '🕵️‍♂️',
    '🧙‍♂️', '🧟‍♂️', '🐉', '🦄',
    '🌺', '🌸'
];

const lastOtpCodes = new Map(); 

function isElementVisible(el) {
    const rect = el.getBoundingClientRect();
    return (
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
}

document.addEventListener("DOMContentLoaded", function() {
    const newLabels = document.querySelectorAll('.new-label');
    
    newLabels.forEach(label => {
        const name = label.id.split('-').pop();
        const createdAt = localStorage.getItem(`otp_created_at_${name}`);
        const now = Date.now();
        const oneHour = 5 * 60 * 1000;

        if (createdAt && (now - createdAt) < oneHour) {
            label.style.display = 'block';
            setTimeout(() => {
                label.style.display = 'none';
            }, oneHour - (now - createdAt));
        }
    });
});

function markNewOTP(name) {
    const now = Date.now();
    localStorage.setItem(`otp_created_at_${name}`, now);
}

async function updateOtpCodes(otpCodes) {
    otpCodes.forEach((otp) => {
        let currentOtpCodeElement = document.getElementById(`current_otp_code_${otp.name}`);
        if (currentOtpCodeElement && isElementVisible(currentOtpCodeElement) && otp.current_otp) {
            const newDigits = otp.current_otp.split('');
            const lastDigits = lastOtpCodes.get(otp.name) ? lastOtpCodes.get(otp.name).split('') : [];
            for (let index = 0; index < newDigits.length; index++) {
                let digitElement = currentOtpCodeElement.querySelectorAll('.digit')[index];
                if (newDigits[index] !== lastDigits[index]) {
                    fadeOutAndIn(digitElement, newDigits[index]);
                }
            }
            lastOtpCodes.set(otp.name, otp.current_otp);
        }
    });
}

function fadeOutAndIn(element, newValue) {
    element.style.transition = 'opacity 0.2s ease-out';
    element.style.opacity = 0;

    setTimeout(() => {
        element.textContent = newValue;
        element.style.transition = 'opacity 0.2s ease-in';
        element.style.opacity = 1;
    }, 200);
}

document.addEventListener('scroll', function() {
    if (typeof refreshOtpCodes === 'function') {
        refreshOtpCodes();
    }
}, {
    passive: true
});

async function refreshOtpCodes() {
    try {
        const response = await fetch('/refresh_codes_v2');
        const data = await response.json();
        updateOtpCodes(data.otp_codes);
    } catch (error) {
        console.error('Fetch error:', error);
    }
}

/*             old rolling effect
async function simulateRolling(digitElement, finalDigit) {
    return new Promise((resolve) => {
        const sequence = [...Array(10).keys()];
        const duration = 200; 
        const startTime = performance.now();

        function animate(time) {
            const elapsedTime = time - startTime;
            const progress = elapsedTime / duration;

            if (progress < 1) {
                const currentDigit = sequence[Math.floor(progress * sequence.length) % sequence.length];
                digitElement.textContent = currentDigit;
                requestAnimationFrame(animate);
            } else {
                digitElement.textContent = finalDigit;
                resolve();
            }
        }

        requestAnimationFrame(animate);
    });
}
*/

async function manuallyRefreshOtps() {
    try {
        const response = await fetch('/refresh_codes_v2');
        const data = await response.json();
        updateOtpCodes(data.otp_codes);
    } catch (error) {
        console.error('Fetch error:', error);
    }
}

function updateNoSecretsMessage() {
    const noSecretsElement = document.getElementById('noSecretsFound');
    if (noSecretsElement) {
        const randomEmoji = emojiList[Math.floor(Math.random() * emojiList.length)];
        noSecretsElement.innerHTML = `No secrets found ${randomEmoji}`;
        noSecretsElement.style.display = 'block'; 
    }
}

function startAutoRefresh() {
    manuallyRefreshOtps();

    let currentTime = new Date();
    let millisTillNextInterval = 30000 - (currentTime.getSeconds() * 1000 + currentTime.getMilliseconds()) % 30000;

    setTimeout(() => {
        manuallyRefreshOtps();
        const intervalId = setInterval(manuallyRefreshOtps, 1000);
        countdownIntervals.set('autoRefreshInterval', intervalId);
    }, millisTillNextInterval);
}

function startCountdown(element, duration) {
    if (countdownIntervals.has(element.id)) {
        clearInterval(countdownIntervals.get(element.id));
    }

    const updateInterval = 50;
    let endTime = calculateNextEndTime(duration);

    function calculateNextEndTime(duration) {
        const currentTime = new Date();
        const secondsPastInterval = currentTime.getSeconds() % duration;
        const millisTillNextInterval = ((duration - secondsPastInterval) % duration) * 1000 - currentTime.getMilliseconds();
        return currentTime.getTime() + millisTillNextInterval;
    }

    function resetProgressBar() {
        element.style.width = '100%';
        endTime = calculateNextEndTime(duration);
    }

    const intervalId = setInterval(() => {
        const currentTime = new Date().getTime();
        const remainingTime = Math.max(endTime - currentTime, 0);
        const remainingSeconds = Math.ceil(remainingTime / 1000);

        element.textContent = remainingSeconds > 0 ? remainingSeconds + "s" : "fetching...";
        element.style.width = `${(remainingTime / (duration * 1000)) * 100}%`;

        if (remainingTime <= 0) {
            resetProgressBar();
            manuallyRefreshOtps();
        }
    }, updateInterval);

    countdownIntervals.set(element.id, intervalId);
}

document.addEventListener('DOMContentLoaded', (event) => {
    document.getElementById('searchInput').value = '';
});

function debounce(func, wait, immediate) {
    let timeout;
    return function() {
        const context = this, args = arguments;
        const later = function() {
            timeout = null;
            if (!immediate) func.apply(context, args);
        };
        const callNow = immediate && !timeout;
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
        if (callNow) func.apply(context, args);
    };
}

function startTimer(elementId, duration) {
    var display = document.getElementById(elementId);
    var exclamation = document.createElement('span');
    exclamation.textContent = ' !';
    exclamation.style.color = 'alert_color'; 

    function updateDisplay() {
        var localTime = new Date();
        var secondsElapsed = localTime.getSeconds() % duration;
        var timer = duration - secondsElapsed - 1;
        var seconds = parseInt(timer % 60, 10);

        seconds = seconds < 10 ? "0" + seconds : seconds;

        if (timer <= 9) {
            display.textContent = "Remaining Time: " + seconds + "s - Expiring";
            display.appendChild(exclamation);

            var flashSpeed = 1;
            if (timer <= 8) flashSpeed = 0.8;
            if (timer <= 7) flashSpeed = 0.6;
            if (timer <= 6) flashSpeed = 0.4;
            if (timer <= 5) flashSpeed = 0.2;

            exclamation.style.animation = `flash ${flashSpeed}s steps(1, end) infinite`;
        } else {
            display.textContent = "Remaining Time: " + seconds + "s";
            if (display.contains(exclamation)) {
                display.removeChild(exclamation);
            }
        }
    }

    function loop() {
        updateDisplay();

        var now = new Date();
        var delay = 1000 - now.getMilliseconds();

        setTimeout(loop, delay);
    }

    loop();
}

document.addEventListener("DOMContentLoaded", function() {
    var flashMessages = document.querySelectorAll(".flash-message");
    flashMessages.forEach(function(msg) {
        msg.style.opacity = "1"; 
        setTimeout(function() {
            msg.style.opacity = "0"; 
        }, 7000);
    });
});

document.addEventListener('DOMContentLoaded', function() {
    var elements = document.querySelectorAll('[id^="timer"]');
    elements.forEach(function(element) {
        if (element) {
            var refreshTime = parseInt(element.getAttribute('data-refresh-time'), 10);
            startTimer(element.id, refreshTime);
        }
    });
});

window.onload = function() {
    let spoilerElements = document.getElementsByClassName('spoiler');
    for (let i = 0; i < spoilerElements.length; i++) {
        let originalText = spoilerElements[i].innerText;
        let maskedText = '●'.repeat(originalText.length);

        spoilerElements[i].innerHTML = `
            <span class="masked-text">${maskedText}</span>
            <span class="original-text" style="opacity: 0;">${originalText}</span>`;

        spoilerElements[i].onmouseover = function() {
            this.querySelector('.original-text').style.opacity = 1;
            this.querySelector('.masked-text').style.opacity = 0;
        };
        spoilerElements[i].onmouseout = function() {
            this.querySelector('.original-text').style.opacity = 0;
            this.querySelector('.masked-text').style.opacity = 1;
        };
    }

    let progressBars = document.getElementsByClassName('progress-bar');
    for (let i = 0; i < progressBars.length; i++) {
        let duration = parseInt(progressBars[i].getAttribute('data-refresh-time')); 
        startCountdown(progressBars[i], duration);
    }

    let otpContainers = document.querySelectorAll('.alert.alert-success');
    otpContainers.forEach(function(container) {
        container.classList.add('fade-in');
    });

    startAutoRefresh();
};

startAutoRefresh();

document.getElementById('searchInput').addEventListener('input', function() {
    var filter = this.value.toUpperCase();
    var rowDiv = document.querySelector('.row'); 
    
    var otpDivs = rowDiv.querySelectorAll('.col-md-4');
    var displayed = 0;
    
    otpDivs.forEach(function(div) {
        var name = div.querySelector('.alert span').textContent || '';  // Get the name or default to empty string
        var email = div.querySelector('.email-tooltip span') ? div.querySelector('.email-tooltip span').textContent || '' : ''; // Get email if available
        var company = div.getAttribute('data-company') || ''; // Get company from data-company attribute

        // Check if the name, email, or company contains the filter
        if (name.toUpperCase().indexOf(filter) > -1 || email.toUpperCase().indexOf(filter) > -1 || company.toUpperCase().indexOf(filter) > -1) {
            div.style.display = 'block';
            displayed++;
        } else {
            div.style.display = 'none';
        }
    });

    var companyGroups = rowDiv.querySelectorAll('.col-md-12.mt-4');
    companyGroups.forEach(function(companyGroup) {
        var nextSibling = companyGroup.nextElementSibling;
        var atLeastOneVisible = false;
        
        // Iterate through all next siblings until the next company group
        while (nextSibling && !nextSibling.matches('.col-md-12.mt-4')) {
            if (nextSibling.style.display !== 'none') {
                atLeastOneVisible = true;
                break;
            }
            nextSibling = nextSibling.nextElementSibling;
        }
        
        // Show or hide the company group based on whether any OTP is visible under it
        if (atLeastOneVisible) {
            companyGroup.style.display = 'block';
        } else {
            companyGroup.style.display = 'none';
        }
    });

    // Show a "no secrets found" message if no OTPs are visible
    if (displayed === 0) {
        document.getElementById('noSecretsFound').style.display = 'block';
        updateNoSecretsMessage();
    } else {
        document.getElementById('noSecretsFound').style.display = 'none';
    }

    refreshOtpCodes();
});

    document.getElementById('searchInput').addEventListener('keydown', function(event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            let query = encodeURIComponent(this.value);

            var otpDivs = document.getElementsByClassName('col-md-4');
            var displayed = 0;
            for (var i = 0; i < otpDivs.length; i++) {
                if (otpDivs[i].style.display !== 'none') {
                    displayed++;
                }
            }
            
            if (displayed === 0) {
                document.getElementById('noSecretsFound').style.display = 'block'; 
            } else {
                document.getElementById('noSecretsFound').style.display = 'none';
                window.location.href = `/search_blueprint/search_otp?page=1&name=${query}`;
            }
        }
    });

    async function copyOTP() {
        try {
            const response = await fetch('/get_otp');
            if (!response.ok) {
                throw new Error('Failed to fetch OTP');
            }
            const data = await response.json();
            if (navigator.clipboard) {
                try {
                    await navigator.clipboard.writeText(data.otpCode);
                } catch (err) {
                    console.error('Clipboard API failed, trying fallback:', err);
                    copyTextToClipboard(data.otpCode); // Using fallback method
                }
            } else {
                console.error('Clipboard API not available, using fallback.');
                copyTextToClipboard(data.otpCode); // Using fallback method
            }
            const clearResponse = await fetch('/clear_otp', { method: 'POST' });
            const clearResult = await clearResponse.json();
            if (!clearResponse.ok || !clearResult.success) {
                throw new Error(clearResult.message || 'Failed to clear OTP');
            }
        } catch (error) {
            console.error('Error copying OTP:', error);
        }
    }
    
    
    async function saveAndCopyOTP(otpName) {
        try {
            const saveResponse = await fetch('/copy_otp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ otpName: otpName }),
            });
            const saveResult = await saveResponse.json();
            if (!saveResponse.ok || !saveResult.success) {
                throw new Error(saveResult.message || 'Failed to save OTP');
            }
    
            await copyOTP();
        } catch (error) {
            console.error('Error saving or copying OTP:', error);
        }
    }
    
    function copyTextToClipboard(text) {
        const textArea = document.createElement("textarea");
        textArea.value = text;
    
        textArea.style.position = "fixed";
        textArea.style.left = "-999999px";
        textArea.style.top = "-999999px";
    
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
    
        try {
            const successful = document.execCommand('copy');
            const msg = successful ? 'successful' : 'unsuccessful';
            console.log('Fallback: Copying text command was ' + msg);
        } catch (err) {
            console.error('Fallback: Oops, unable to copy', err);
        }
    
        document.body.removeChild(textArea);
    }    

    let originalOtpName;

    function openEditModal(name, secret, company) {
        originalOtpName = name; 
    
        document.getElementById('editOtpName').value = name;
        document.getElementById('editOtpSecret').value = secret;
    
        const secretField = document.getElementById('editOtpSecret');
        secretField.addEventListener('input', function() {
            let inputValue = this.value.toUpperCase();
            if (inputValue.length > 16) {
                inputValue = inputValue.substr(0, 16);
            }
            this.value = inputValue;
        });
        
        secretField.addEventListener('focus', function() {
            this.type = 'text';
        });
    
        secretField.addEventListener('blur', function() {
            this.type = 'password'; 
        });

        console.log("Setting company select value to: ", company);
    
        setTimeout(function() {
            $('#editModal').modal('show');
        }, 100); 
    }    

    function saveEdit() {
        var editedName = document.getElementById('editOtpName').value;
        var editedSecret = document.getElementById('editOtpSecret').value;
        var editedCompany = document.getElementById('editOtpCompany').value;
    
        fetch('/edit/' + originalOtpName, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({
                name: editedName,
                secret: editedSecret,
                company: editedCompany,
            })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            console.log(data.message);
            $('#editModal').modal('hide');
            window.location.reload();
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }

    function showToast() {
        var toast = document.getElementById('toast');
        toast.style.display = 'block';

        setTimeout(function() {
            toast.classList.add('toast-show');
        }, 10);

        setTimeout(function() {
            toast.classList.remove('toast-show');
            setTimeout(function() {
                toast.style.display = 'none';
            }, 500); 
        }, 5000); 
    }

    let formToSubmit;

    document.addEventListener('DOMContentLoaded', (event) => {
        document.querySelectorAll('.delete-btn').forEach((button) => {
            button.addEventListener('click', function() {
                let otpName = this.getAttribute('data-otp-name');
                formToSubmit = document.getElementById(`deleteForm_${otpName}`);
            });
        });
        
        document.getElementById('deleteConfirmationButton').onclick = () => {
            formToSubmit.submit();
        };
    });

    document.addEventListener("DOMContentLoaded", function() {
        function getGreeting() {
            let now = new Date();
            let hour = now.getHours();
            if (hour < 4) {
                return "🌜 It's getting late";
            } else if (hour < 12) {
                return "☕ Good morning";
            } else if (hour < 18) {
                return "🌞 Good afternoon";
            } else {
                return "🌒 Good evening";
            }
        }
    
        let greeting = getGreeting();
        let searchPrompt = "Type here to search for OTPs";
        let placeholderText = `${greeting} ${username}! ${searchPrompt}`;
        let input = document.getElementById("searchInput");
        input.setAttribute("placeholder", placeholderText);
    
        function updateClock() {
            let currentTime = getCurrentTime(); 
            input.setAttribute("placeholder", `${placeholderText} - ${currentTime}`);
            setTimeout(updateClock, 1000);
        }
    
        function getCurrentTime() {
            let now = new Date();
            let hours = now.getHours().toString().padStart(2, '0');
            let minutes = now.getMinutes().toString().padStart(2, '0');
            let seconds = now.getSeconds().toString().padStart(2, '0');
            return `${hours}:${minutes}:${seconds}`;
        }
    
        updateClock(); 
    });