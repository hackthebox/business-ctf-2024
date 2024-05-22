function submitCommand() {
    const radios = document.forms['commandForm'].elements['command'];
    let choiceIndex = -1;

    for (let i = 0; i < radios.length; i++) {
        if (radios[i].checked) {
            choiceIndex = i;
            break;
        }
    }

    if (choiceIndex === -1) {
        return false;
    }

    fetch('/server_status', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `choice=${encodeURIComponent(choiceIndex)}`
    })
    .then(response => response.text())
    .then(data => {
        document.getElementById('response').textContent = data;
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById('response').textContent = 'Failed to fetch data';
    });
    return false;
}