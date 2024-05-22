
async function getToken() {
    let currentToken = localStorage.getItem("token");

    if (!currentToken) {
        try {
            const response = await fetch('/getToken');
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            const token = await response.text();
            localStorage.setItem("token", token);
            console.log(token);
            return token;
        } catch (error) {
            console.error('There was an error!', error);
            return null;
        }
    }
    return currentToken;
}


  async function downloadReport(url, filename) {
    const token = await getToken()

    fetch(`/download?token=${token}`, {
    method: 'POST',
    body: new URLSearchParams({url: window.location.href + url})
    })
    .then(res => res.blob())
    .then(blob => {
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename + '.pdf';
        document.body.appendChild(link);
        link.click();
        link.remove();
    })
    .catch(error => {
        console.log("Error " + error)
    })
}
