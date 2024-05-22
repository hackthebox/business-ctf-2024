$(document).ready(function() {
    $('.list-item').on('click', function() {
        let topic = $(this).data('topic');
        if (topic) {
            $('.list-item').addClass('hidden');
            $('#loading-item').removeClass('hidden');
            createRoom(topic);
        }
    });
});

const toggleProps = (state) => {
    $('#url').prop('disabled', state);
    $('#ask-btn').prop('disabled', state);
}

const createRoom = async (topic) => {

    await fetch('/api/create', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ topic })
    }).then(async (res) => {
        if (res.status === 201) {
            let data = await res.json();
            window.location.href = `/chat/${data.room}?topic=${data.topic}`;
        } else {
            $('.list-item').removeClass('hidden');
            $('#loading-item').addClass('hidden');
            $('#resp-item').removeClass('hidden');
        }
    }
    ).catch((err) => {
        $('.list-item').removeClass('hidden');
        $('#loading-item').addClass('hidden');
        $('#resp-item').removeClass('hidden');
    });
}