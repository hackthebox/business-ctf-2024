

var songs = [
    "A Wonderful Guy - Diamond City Radio - Fallout 4.mp3",
    "Accentuate the Positive - Bing Crosby - Fallout 4.mp3",
    "Anything Goes - Diamond City Radio - Fallout 4.mp3",
    "Atom Bomb Baby - Diamond City Radio - Fallout 4.mp3",
    "Butcher Pete - Roy Brown.mp3",
    "Crazy He Calls Me - Billie Holiday - Fallout 3.mp3",
    "Civilization - Fallout 3 .mp3",
    "The End of the World - Skeeter Davis - Fallout 4.mp3",
    "The Wanderer - Dion And Belmonts.mp3",
    "Uranium Fever - Fallout 4.mp3",
    "A Kiss to Build a Dream On - Louis Armstrong.mp3",
    "Ain't That A Kick In The Head.mp3",
    "Big Iron - Marty Robbins.mp3",
    "Rocket 69 - Connie Allen .mp3",
    "Take Me Home, Country Roads - Fallout 76.mp3"
  ];

  $('a').on('click', function(e){
    $('a').removeClass('music-focus');
    $(e.currentTarget).addClass('music-focus');
});

var songSlider = document.getElementById('songSlider');
var song = new Audio();
var currentSong = 0; 
function loadSong (which){
    song.src = "/static/music/" + songs[which];
    song.play();
    currentSong = which;
    document.getElementById('play-pause-check').src='/static/music/pause button.png';
    setTimeout(showDuration, 1000);
    $(document).ready(function(){
      $('.wave').css({
        top: "220px",
      });
      $('.wave span').addClass('wave-span-active');
    });
}
setInterval(updateSongSlider, 500);
function updateSongSlider(){
  var c = Math.round(song.currentTime);
  songSlider.value = c;
  if(song.ended){
    next();
  }
}

function showDuration(){
  var d = Math.floor(song.duration);
  songSlider.setAttribute("max", d);
}
function playPause(img){
  if(song.paused){
    song.play();
    img.src = "/static/music/pause button.png";
    $(document).ready(function(){
      $('.wave').css({
        top: "220px",
      });
      $('.wave span').addClass('wave-span-active');
    });
  }else{
    song.pause();
    img.src = "/static/music/play button.png";
    $(document).ready(function(){
      $('.wave').css({
        top: "220px",
      });
      $('.wave span').removeClass('wave-span-active');
    });
  }
}
  
function next(){
  currentSong = (currentSong + 1) % songs.length;
  loadSong(currentSong);
  $(this).on('click', function(e){
    var whenPressedNext = document.getElementsByClassName('music-focus');
    var dadu = $(whenPressedNext).nextSibling;
    $(whenPressedNext).removeClass('music-focus');

    $(dadu).addClass('music-focus');
  });
}
function previous(){
  currentSong--;
  currentSong = (currentSong < 0) ? (songs.length - 1) : currentSong;
  loadSong(currentSong);
}
function replay(currenSong){
    loadSong(currentSong);
}
function seekSong(){
    song.currentTime = songSlider.value;
}
function mute(mute_image){
    if(song.volume == 0){
        song.volume = 1;
        mute_image.src = "/static/music/mute.png";
    }else{
        song.volume = 0;
        mute_image.src = "/static/music/mute active.png";
    }
}
function shuffle(){
  myShuffle();
  console.log(songs);
}
function myShuffle(){
  var currentIndex = songs.length, temporaryValue, randomIndex;

  while(currentIndex !== 0){
    randomIndex = Math.floor(Math.random() * currentIndex);
    currentIndex--;

    temporaryValue = songs[currentIndex];
    songs[currentIndex] = songs[randomIndex];
    songs[randomIndex] = temporaryValue;
  }
  return songs;
}