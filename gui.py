import npyscreen
import sys

class FuzzyForm(npyscreen.Form):
    def create(self):
        self.ip_or_app = self.add(npyscreen.TitleMultiSelect,max_height=3, name='LAYER TO FUZZ', values=['IP', 'Application'],scroll_exit=True)
        # self.duration = self.add(npyscreen.TitleText, name="Duration Value: " )
        # self.fileName = self.add(npyscreen.TitleFilename, name="Filename:" )
        self.ip_default_or_file = self.add(npyscreen.TitleSelectOne, max_height=4, name='IP LAYER', values=['Default Tests', 'File (please edit ip_from_file.txt)'], scroll_exit=True)
        self.ip_user_specified_field = self.add(npyscreen.TitleSelectOne, max_height=8, name='IP LAYER - specific fields (leave blank to test all)', values=['version', 'internet_header_length', 'type_of_service', 'length_of_packet', 'id_of_packet', 'flags', 'frag', 'time_to_live', 'protocol', 'copy_flag', 'optclass', 'option'], scroll_exit=True)
        self.ip_user_specified_number_values = self.add(npyscreen.TitleText, name="IP LAYER - Number of random values to test (1-1000, else default applied): " )

        # self.fileName = self.add(npyscreen.TitleFilenameCombo, name="IP LAYER - packet from file:" )


        self.app_default_or_file = self.add(npyscreen.TitleSelectOne, max_height=4, name='APPLICATION LAYER', values=['Default Tests', 'File (please edit application_from_file.txt)'], scroll_exit=True)
        self.app_packets_number = self.add(npyscreen.TitleText, name="APPLICATION LAYER - Number of Packets (blank for default): " )
        self.app_payload_size = self.add(npyscreen.TitleText, name="APPLICATION LAYER - Payload Size (blank for default): " )
        self.app_payload_variable_low = self.add(npyscreen.TitleText, name="APPLICATION LAYER - Variable-Length ==>low<== (blank for default): " )
        self.app_payload_variable_high = self.add(npyscreen.TitleText, name="APPLICATION LAYER - Variable-Length ==>high<== (blank for default): " )

        # self.myDate = self.add(npyscreen.TitleDateCombo, name='Date Employed')
        # self.stats = self.add(npyscreen.TitleMultiSelect, max_height=5, name='Capture Statistics',
        #                              values=['Conversations', 'http', 'DNS', 'Endpoints','Follow TCP/UDP'], scroll_exit=True)

def myFunction(*args):
    F = FuzzyForm(name = "FuZzER")
    F.edit()
    ip_or_app = F.ip_or_app.value
    ip_default_or_file = F.ip_default_or_file.value
    ip_user_specified_field = F.ip_user_specified_field.value
    ip_user_specified_number_values = F.ip_user_specified_number_values.value

    app_default_or_file = F.app_default_or_file.value
    app_packets_number = F.app_packets_number.value
    app_payload_size = F.app_payload_size.value
    app_payload_variable_low = F.app_payload_variable_low.value
    app_payload_variable_high = F.app_payload_variable_high.value

    values = {}
    all_options = ['ip_or_app', 'ip_default_or_file', 'ip_user_specified_field', 'ip_user_specified_number_values', 'app_default_or_file', 'app_packets_number', 'app_payload_size', 'app_payload_variable_low', 'app_payload_variable_high']

    values['ip_fuzzing'] = 'no'
    values['app_fuzzing'] = 'no'
    if ip_or_app:
        if ip_or_app[0] == 0:
            values['ip_fuzzing'] ='yes'
        if ip_or_app[0] == 1 or len(ip_or_app) == 2:
            values['app_fuzzing'] ='yes'

    if ip_default_or_file or values['ip_fuzzing'] == 'yes':
        if values['ip_fuzzing'] == 'yes' or ip_default_or_file[0] == 0:
            values['ip_default_or_file'] = 'default'
            values['ip_fuzzing'] ='yes'
        try:
            if ip_default_or_file[0] == 1:
                values['ip_default_or_file'] = 'file'
                values['ip_fuzzing'] ='yes'
        except:
            pass

    if ip_user_specified_field:
        try:
            if ip_user_specified_field[0] == 0:
                values['ip_user_specified_field'] = 'version'
                values['ip_fuzzing'] ='yes'
                values['ip_default_or_file'] = 'default'
                # break
            if ip_user_specified_field[0] == 1:
                values['ip_user_specified_field'] = 'internet_header_length'
                values['ip_fuzzing'] ='yes'
                values['ip_default_or_file'] = 'default'
                # break
            if ip_user_specified_field[0] == 2:
                values['ip_user_specified_field'] = 'type_of_service'
                values['ip_fuzzing'] ='yes'
                values['ip_default_or_file'] = 'default'
                # break
            if ip_user_specified_field[0] == 3:
                values['ip_user_specified_field'] = 'length_of_packet'
                values['ip_fuzzing'] ='yes'
                values['ip_default_or_file'] = 'default'
                # break
            if ip_user_specified_field[0] == 4:
                values['ip_user_specified_field'] = 'id_of_packet'
                values['ip_fuzzing'] ='yes'
                values['ip_default_or_file'] = 'default'
                # break
            if ip_user_specified_field[0] == 5:
                values['ip_user_specified_field'] = 'flags'
                values['ip_fuzzing'] ='yes'
                values['ip_default_or_file'] = 'default'
                # break
            if ip_user_specified_field[0] == 6:
                values['ip_user_specified_field'] = 'frag'
                values['ip_fuzzing'] ='yes'
                values['ip_default_or_file'] = 'default'
                # break
            if ip_user_specified_field[0] == 7:
                values['ip_user_specified_field'] = 'time_to_live'
                values['ip_fuzzing'] ='yes'
                values['ip_default_or_file'] = 'default'
                # break
            if ip_user_specified_field[0] == 8:
                values['ip_user_specified_field'] = 'protocol'
                values['ip_fuzzing'] ='yes'
                values['ip_default_or_file'] = 'default'
                # break
            if ip_user_specified_field[0] == 9:
                values['ip_user_specified_field'] = 'copy_flag'
                values['ip_fuzzing'] ='yes'
                values['ip_default_or_file'] = 'default'
                # break
            if ip_user_specified_field[0] == 10:
                values['ip_user_specified_field'] = 'optclass'
                values['ip_fuzzing'] ='yes'
                values['ip_default_or_file'] = 'default'
                # break
            if ip_user_specified_field[0] == 11:
                values['ip_user_specified_field'] = 'option'
                values['ip_fuzzing'] ='yes'
                values['ip_default_or_file'] = 'default'
                # break
        except:
            pass

    if ip_user_specified_number_values:
        values['ip_default_or_file'] = 'default'
        values['ip_fuzzing'] ='yes'
        if ip_user_specified_field:
            values['ip_user_specified_field'] = None
        values['ip_user_specified_number_values'] = 'default'
        try:
            if int(ip_user_specified_number_values) >= 1 and int(ip_user_specified_number_values) <= 1000:
                values['ip_user_specified_number_values'] = int(ip_user_specified_number_values)
            else:
                values['ip_user_specified_number_values'] = 'default'
        except:
            pass

#------------------------------------------------------------------------------#

    if app_default_or_file or values['app_fuzzing'] == 'yes':
        if values['app_fuzzing'] == 'yes' or app_default_or_file[0] == 0:
            values['app_default_or_file'] = 'default'
            values['app_payload_size'] = 'default'
            values['app_payload_variable_low'] = 'default'
            values['app_payload_variable_high'] = 'default'
            values['app_packets_number'] = 'default'
            values['app_fuzzing'] ='yes'
        try:
            if app_default_or_file[0] == 1:
                values['app_default_or_file'] = 'file'
                values['app_fuzzing'] ='yes'
        except:
            pass

    if app_packets_number or values['app_fuzzing'] == 'yes':
        if not app_default_or_file:
            values['app_default_or_file'] = 'default'
        values['app_payload_size'] = 'default'
        values['app_payload_variable_low'] = 'default'
        values['app_payload_variable_high'] = 'default'
        values['app_packets_number'] = 'default'
        values['app_fuzzing'] = 'yes'
        try:
            if int(app_packets_number) >= 1 and int(app_packets_number) <= 1000:
                values['app_packets_number'] = int(app_packets_number)
        except:
            pass

    if app_payload_size or values['app_fuzzing'] == 'yes':
        values['app_payload_size'] = 'default'
        if not app_default_or_file:
            values['app_default_or_file'] = 'default'
        if not app_packets_number:
            values['app_packets_number'] = 'default'
        values['app_payload_variable_low'] = 'default'
        values['app_payload_variable_high'] = 'default'
        values['app_fuzzing'] = 'yes'
        try:
            if int(app_payload_size) >= 1 and int(app_payload_size) <= 1000:
                values['app_payload_size'] = int(app_payload_size)
        except:
            pass

    if app_payload_variable_low or app_payload_variable_high:
        if not app_payload_size:
            values['app_payload_size'] = 'default'
        if not app_default_or_file:
            values['app_default_or_file'] = 'default'
        if not app_packets_number:
            values['app_packets_number'] = 'default'
        values['app_payload_variable_low'] = 'default'
        values['app_payload_variable_high'] = 'default'
        try:
            if int(app_payload_variable_low) >= 1 and int(app_payload_variable_low) <= 1000:
                values['app_payload_variable_low'] = int(app_payload_variable_low)
            if int(app_payload_variable_high) >= 1 and int(app_payload_variable_high) <= 1000:
                values[app_payload_variable_high] = int(app_payload_variable_high)
        except:
            pass

    for item in all_options:
        if item not in values:
            values[item] = None

    return values

def script():
    try:
        return npyscreen.wrapper_basic(myFunction)
    except:
        print("[-] please make the terminal window larger to use this GUI")
        return False
