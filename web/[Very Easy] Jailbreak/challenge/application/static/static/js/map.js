function realtimeClock(){
    var rtc = new Date();
    var hours = rtc.getHours();
    var minutes = rtc.getMinutes();
    var seconds = rtc.getSeconds();
    var ampm = (hours < 12) ? "AM" : "PM";
    hours = (hours > 12) ? hours-12 : hours;
    hours = ("0" + hours).slice(-2);
    minutes = ("0" + minutes).slice(-2);
    seconds = ("0" + seconds).slice(-2);
    document.getElementById('clock').innerHTML = hours + ":" + minutes + ":" + seconds + " " + ampm;
    var t = setTimeout(realtimeClock, 500);
  }
  realtimeClock();
  
  function realTimeDate(){
    var dateToday = new Date();
    var day = dateToday.getDate();
    var month = dateToday.getMonth();
    var year = dateToday.getFullYear();
    document.getElementById('my_date').innerHTML = day + "." + (month + 1) + "." + year;
  }
  realTimeDate();
  