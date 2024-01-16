const countdownIntervals = new Map();

async function updateOtpCodes(otpCodes) {
    otpCodes.forEach(otp => {
        let otpCodeElement = document.getElementById(`otp_code_${otp.name}`);
        let progressBar = document.getElementById(`progressBar${otp.name}`);

        if (otpCodeElement) {
            otpCodeElement.textContent = otp.otp_code;
        }

        if (progressBar) {
            progressBar.style.width = '100%';
            let duration = parseInt(progressBar.getAttribute('data-refresh-time'));
            startCountdown(progressBar, duration);
        }
    });
}

async function manuallyRefreshOtps() {
    try {
        const response = await fetch('/refresh_codes_v2');
        const data = await response.json();
        updateOtpCodes(data.otp_codes);
    } catch (error) {
        console.error('Fetch error:', error);
    }
}

function startAutoRefresh() {
    manuallyRefreshOtps();

    let currentTime = new Date();
    let millisTillNextInterval = 30000 - (currentTime.getSeconds() * 1000 + currentTime.getMilliseconds()) % 30000;

    setTimeout(() => {
        manuallyRefreshOtps();
        const intervalId = setInterval(manuallyRefreshOtps, 30000);
        countdownIntervals.set('autoRefreshInterval', intervalId);
    }, millisTillNextInterval);
}

function startCountdown(element, duration) {
    element.textContent = "calculating expiry..."; 

    if (countdownIntervals.has(element.id)) {
        clearInterval(countdownIntervals.get(element.id));
    }

    const intervalId = setInterval(() => {
        let current_time = new Date().getSeconds();
        let remaining = duration - (current_time % duration);

        if (remaining === 0) {
            element.textContent = "expiering...";
        } else if (remaining === 1) {
            let otpName = element.id.replace('progressBar', '');
            let otpCodeElement = document.getElementById(`otp_code_${otpName}`);
            if (otpCodeElement) {
                otpCodeElement.classList.add('flash');
                setTimeout(() => otpCodeElement.classList.remove('flash'), 3000);
            }
        } else {
            element.textContent = remaining + "s";
        }

        element.style.width = `${(remaining / duration * 100)}%`;

        if (remaining <= 1) {
            clearInterval(countdownIntervals.get(element.id));
            manuallyRefreshOtps();
        }
    }, 1000);

    countdownIntervals.set(element.id, intervalId);
}

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
        spoilerElements[i].setAttribute('data-original', originalText);
        spoilerElements[i].innerText = '●'.repeat(originalText.length);
        spoilerElements[i].onmouseover = function() {
            this.innerText = this.getAttribute('data-original');
        }
        spoilerElements[i].onmouseout = function() {
            this.innerText = '●'.repeat(this.getAttribute('data-original').length);
        }
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

document.getElementById('searchInput').addEventListener('input', function() {
    var filter = this.value.toUpperCase();
    var rowDiv = document.querySelector('.row'); 
    
    var otpDivs = rowDiv.querySelectorAll('.col-md-4');
    var displayed = 0;
    otpDivs.forEach(function(div) {
        var name = div.querySelector('.alert').textContent;
        if (name.toUpperCase().indexOf(filter) > -1) {
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
            
            while (nextSibling && !nextSibling.matches('.col-md-12.mt-4')) {
                if (nextSibling.style.display !== 'none') {
                    atLeastOneVisible = true;
                    break;
                }
                nextSibling = nextSibling.nextElementSibling;
            }
            
            if (atLeastOneVisible) {
                companyGroup.style.display = 'block';
            } else {
                companyGroup.style.display = 'none';
            }
        });

        if (displayed === 0) {
            document.getElementById('noSecretsFound').style.display = 'block';
        } else {
            document.getElementById('noSecretsFound').style.display = 'none';
        }
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

    function copyToClipboard(element) {
        let text = element.textContent;
        navigator.clipboard.writeText(text).then(() => {
            showToast();
        }).catch(err => {
            console.error('Fehler beim Kopieren: ', err);
        });
    }
    
    let originalOtpName;

    function openEditModal(name, secret, company) {
        originalOtpName = name; 
    
        document.getElementById('editOtpName').value = name;
        document.getElementById('editOtpSecret').value = secret;
    
        const secretField = document.getElementById('editOtpSecret');
        secretField.value = secret;
    
        secretField.addEventListener('focus', function() {
            this.type = 'text'; // Show the secret when focused
        });
    
        secretField.addEventListener('blur', function() {
            this.type = 'password'; // Hide the secret when not focused
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
        let placeholders = [
        "Search for One-Time Passwords",
        "Press Enter to Display All Results",
        "Type a Company Name to Search Directly",
        "Keine Ahnung was ich hier einfügen soll..",
        "Use Keywords to Narrow Down Results",
        "Python Python Python; Bim Bim Bam Bam, hehehaha",
        "Enter the Name of the OTP for Immediate Retrieval"
        ];

        let randomIndex = Math.floor(Math.random() * placeholders.length);
        let selectedPlaceholder = placeholders[randomIndex];

        let placeholderText = Array.from(selectedPlaceholder);
        let input = document.getElementById("searchInput");

        let i = 0;
        let placeholderInterval = setInterval(function(){
            if(i < placeholderText.length){
            input.setAttribute("placeholder", input.getAttribute("placeholder") + placeholderText[i]);
            i++;
            } else {
            clearInterval(placeholderInterval);
            }
        }, 100);
    });