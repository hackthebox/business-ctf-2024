from flask import Blueprint, render_template, request, make_response
from lxml import etree

web = Blueprint('web', __name__)
api = Blueprint('api', __name__)

@web.route('/')
def index():
    return render_template('index.html')

@web.route('/data')
def data():
    return render_template('data.html')

@web.route('/inventory')
def inventory():
    return render_template('inventory.html')

@web.route('/map')
def map():
    return render_template('map.html')

@web.route('/radio')
def radio():
    return render_template('radio.html')

@web.route('/rom')
def rom():
    return render_template('rom.html')

@api.route('/update', methods=['POST'])
def update_firmware():
    if request.content_type == 'application/xml':
        try:
            xml_input = request.get_data(as_text=True)
           
            parser = etree.XMLParser(load_dtd=True, no_network=False, resolve_entities=True)
            tree = etree.fromstring(xml_input, parser=parser)
            
            if tree.tag != 'FirmwareUpdateConfig':
                raise ValueError('The root element must be \'FirmwareUpdateConfig\'.')

            firmware_element = tree.find('Firmware')
            if firmware_element is None:
                raise ValueError('The \'Firmware\' element is missing from the provided XML.')

            version_element = firmware_element.find('.//Version')
            if version_element is None:
                raise ValueError('The \'Version\' element is missing from the \'Firmware\' element.')
            
            firmware_version = version_element.text
            response_message = f'Firmware version {firmware_version} update initiated.'

            return make_response({'message': response_message}, 200)
        except Exception as e:
            return make_response({'message': f'An error occurred: {str(e)}'}, 400)
    else:
        return make_response({'message': 'Unsupported Media Type. Please send application/xml'}, 415)