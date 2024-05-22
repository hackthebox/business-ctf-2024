$(document).ready(function(){
  let weapons = [
    {
      "name" : "44_pistol",
      "damage" : 48,
      "fire_rate" : 6,
      "range" : 119,
      "accuracy" : 66,
      "weight" : 4.2,
      "value" : 99,
      "weapons_image": "<img src='/static/images/44 Pistol.png'>"
    },
    {
      "name" : "laser_gun",
      "damage" : 24,
      "fire_rate" : 50,
      "range" : 71,
      "accuracy" : "-",
      "weight" : 3.5,
      "value" : 69,
      "weapons_image": "<img src='/static/images/laser pistol.png'>"
    },
    {
      "name" : "plasma_gun",
      "damage" : 48,
      "fire_rate" : 33,
      "range" : 119,
      "accuracy" : "-",
      "weight" : 3.9,
      "value" : 123,
      "weapons_image": "<img src='/static/images/plasma pistol.png'>"
    },
    {
      "name" : "assault_rifle",
      "damage" : 30,
      "fire_rate" : 40,
      "range" : 119,
      "accuracy" : 72,
      "weight" : 13.1,
      "value" : 144,
      "weapons_image": "<img src='/static/images/AssaultRifle.png'>"
    },
    {
      "name" : "combat_shotgun",
      "damage" : 50,
      "fire_rate" : 20,
      "range" : 47,
      "accuracy" : 23,
      "weight" : 11.1,
      "value" : 87,
      "weapons_image": "<img src='/static/images/combat shotgun.png'>"
    },
    {
      "name" : "gauss_rifle",
      "damage" : 110,
      "fire_rate" : 66,
      "range" : 191,
      "accuracy" : 69,
      "weight" : 15.8,
      "value" : 228,
      "weapons_image": "<img src='/static/images/Gauss rifle.png'>"
    },
    {
      "name" : "submachine_gun",
      "damage" : 10,
      "fire_rate" : 127,
      "range" : 107,
      "accuracy" : 63,
      "weight" : 12.7,
      "value" : 109,
      "weapons_image": "<img src='/static/images/Submachine gun1.png'>"
    },
    {
      "name" : "cosmic_cannon",
      "damage" : 36,
      "fire_rate" : 90,
      "range" : 77,
      "accuracy" : 72,
      "weight" : 5.5,
      "value" : 95,
      "weapons_image": "<img src='/static/images/Cosmic cannon.png'>"
    },
    {
      "name" : "grenade",
      "damage" : 151,
      "fire_rate" : "-",
      "range" : '-',
      "accuracy" : '-',
      "weight" : '0.5',
      "value" : 50,
      "weapons_image": "<img src='/static/images/grenade.png'>"
    },
    {
      "name" : "molotov",
      "damage" : 51,
      "fire_rate" : "-",
      "range" : "-",
      "accuracy" : "-",
      "weight" : 0.5,
      "value" : 20,
      "weapons_image": "<img src='/static/images/Molotov.png'>"
    },
    {
      "name" : "axe",
      "damage" : 25,
      "fire_rate" : 3,
      "range" : "close",
      "accuracy" : "-",
      "weight" : 10,
      "value" : 100,
      "weapons_image": "<img src='/static/images/Grognaks axe1.png'>"
    } 
  ];

 
  $('.item-list a').on('click', function(e){
    $('.item-list a').removeClass('active');
    $(e.currentTarget).addClass('active');
  });

  
  $('.item-list a').on('mouseenter', function(e){
    let current_item = $(e.currentTarget).attr('class');
    for(item in weapons){
      if(weapons[item].name == current_item){
        let container = $('.item-stats');
        let container2 = $('.weapon-placeholder');
        container.find('.damage').html(weapons[item].damage);
        container.find('.fire_rate').html(weapons[item].fire_rate);
        container.find('.range').html(weapons[item].range);
        container.find('.accuracy').html(weapons[item].accuracy);
        container.find('.weight').html(weapons[item].weight);
        container.find('.value').html(weapons[item].value);
        container2.find('.weapon_div').html(weapons[item].weapons_image);
      }
    }
  });
  
  
  $('.item-list a').on('mouseleave', function(){
        let container = $('.item-stats');
        let container2 = $('.weapon-placeholder');
        container.find('.damage').html("-");
        container.find('.fire_rate').html("-");
        container.find('.range').html("-");
        container.find('.accuracy').html("-");
        container.find('.weight').html("-");
        container.find('.value').html("-");
        container2.find('.weapon_div').html("");
    });

  
  $('.item-list a').on('mouseleave', function(){
    var current_item = $(':focus');
    current_item = $(':focus').attr('class');
    console.log(current_item);
    for(item in weapons){
      if(weapons[item].name + ' active' == current_item){
        console.log("inside if");
        let container = $('.item-stats');
        let container2 = $('.weapon-placeholder');
        container.find('.damage').html(weapons[item].damage);
        container.find('.fire_rate').html(weapons[item].fire_rate);
        container.find('.range').html(weapons[item].range);
        container.find('.accuracy').html(weapons[item].accuracy);
        container.find('.weight').html(weapons[item].weight);
        container.find('.value').html(weapons[item].value);
        container2.find('.weapon_div').html(weapons[item].weapons_image);
      }
    }
  });
})


