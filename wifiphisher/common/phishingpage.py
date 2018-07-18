"""This module handles all the phishing related operations."""

from __future__ import (absolute_import, division, print_function)
import os
import ConfigParser
from shutil import copyfile
import wifiphisher.common.constants as constants


def config_section_map(config_file, section):
    """Map the values of a config file to a dictionary."""
    config = ConfigParser.ConfigParser()
    config.read(config_file)
    dict1 = {}

    if section not in config.sections():
        return dict1

    options = config.options(section)
    for option in options:
        try:
            dict1[option] = config.get(section, option)
        except KeyError:
            dict1[option] = None
    return dict1


class InvalidTemplate(Exception):
    """Exception class to raise in case of a invalid template."""

    pass


class PhishingTemplate(object):
    """This class represents phishing templates."""

    def __init__(self, name):
        # type: (str) -> None
        """Intialize the class with all arguments."""
        config_path = os.path.join(constants.PHISHING_PAGES_DIR, name,
                                   'config.ini')
        info = config_section_map(config_path, 'info')

        self._name = name
        self.display_name = info['name']
        self._description = info['description']
        self._payload = False
        self._config_path = os.path.join(constants.PHISHING_PAGES_DIR,
                                         self._name, 'config.ini')
        if 'payloadpath' in info:
            self._payload = info['payloadpath']

        self.path = os.path.join(constants.PHISHING_PAGES_DIR,
                                 self._name.lower(),
                                 constants.SCENARIO_HTML_DIR)
        self.static_path = os.path.join(constants.PHISHING_PAGES_DIR,
                                        self._name.lower(),
                                        constants.SCENARIO_HTML_DIR, 'static')

        self.context = config_section_map(config_path, 'context')
        self._extra_files = []

    @staticmethod
    def update_config_file(payload_filename, config_path):
        # type: (str, str) -> None
        """Update the configuration file."""
        original_config = ConfigParser.ConfigParser()
        original_config.read(config_path)

        # new config file object
        config = ConfigParser.RawConfigParser()

        # update the info section
        config.add_section('info')
        options = original_config.options('info')
        for option in options:
            if option != "payloadpath":
                config.set('info', option, original_config.get('info', option))
            else:
                dirname = os.path.dirname(
                    original_config.get('info', 'payloadpath'))
                filepath = os.path.join(dirname, payload_filename)
                config.set('info', option, filepath)

        # update the context section
        config.add_section('context')
        dirname = os.path.dirname(
            original_config.get('context', 'update_path'))
        filepath = os.path.join(dirname, payload_filename)
        config.set('context', 'update_path', filepath)
        with open(config_path, 'wb') as configfile:
            config.write(configfile)

    def update_payload_path(self, filename):
        # type: (str) -> None
        """Update the payload path."""
        config_path = self._config_path
        self.update_config_file(filename, config_path)
        # update payload attribute
        info = config_section_map(config_path, 'info')
        self._payload = False
        if 'payloadpath' in info:
            self._payload = info['payloadpath']

        self._context = config_section_map(config_path, 'context')
        self._extra_files = []

    def merge_context(self, context):
        """Merge dict context with current one.

        In case of confict always keep current values.
        """
        context.update(self._context)
        self._context = context

    def get_payload_path(self):
        """Return the payload path of the template."""
        return self._payload

    def has_payload(self):
        """Return whether the template has a payload."""
        return bool(self._payload)

    def use_file(self, path):
        # type: (str) -> Optional[str]
        """Copy a file in the filesystem to the path of the template files."""
        if path and os.path.isfile(path):
            filename = os.path.basename(path)
            copyfile(path, self.static_path + filename)
            self._extra_files.append(self.static_path + filename)
            return filename

    def remove_extra_files(self):
        # type: () -> None
        """Remove extra used files."""
        for filename in self._extra_files:
            if os.path.isfile(filename):
                os.remove(filename)

    def __str__(self):
        # type: () -> str
        """Return a string representation of the template."""
        return "{display_name}\n\t{_description}\n".format(
            display_name=self.display_name, _description=self._description)


class TemplateManager(object):
    """Handles all the template management operations."""

    def __init__(self):
        """Initialize the class."""
        # setup the templates
        self._template_directory = constants.PHISHING_PAGES_DIR

        page_dirs = os.listdir(constants.PHISHING_PAGES_DIR)

        self.templates = {}

        for page in page_dirs:
            if os.path.isdir(page) and self.is_valid_template(page)[0]:
                self.templates[page] = PhishingTemplate(page)

        # add all the user templates to the database
        self.add_user_templates()

    def is_valid_template(self, name):
        # type: (str) -> Tuple[bool, str]
        """Validate the template."""
        html = False
        dir_path = os.path.join(self._template_directory, name)
        # check config file...
        if "config.ini" not in os.listdir(dir_path):
            return False, "Configuration file not found in: "
        try:
            tdir = os.listdir(
                os.path.join(dir_path, constants.SCENARIO_HTML_DIR))
        except OSError:
            return False, "No " + constants.SCENARIO_HTML_DIR + " directory found in: "
        # Check HTML files...
        for tfile in tdir:
            if tfile.endswith(".html"):
                html = True
                break
        if not html:
            return False, "No HTML files found in: "
        # and if we found them all return true and template directory name
        return True, name

    def find_user_templates(self):
        # type: () -> List[str]
        """Return all the user's templates available."""
        local_templates = []  # type: List[str]

        for name in os.listdir(self._template_directory):
            # check to see if it is a directory and not in the database
            if (os.path.isdir(os.path.join(self._template_directory, name))
                    and name not in self.templates):
                # check template
                is_valid, output = self.is_valid_template(name)
                # if template successfully validated, then...
                if is_valid:
                    local_templates.append(name)
                else:
                    # TODO: We should throw an exception instead here.
                    # but if not then display which problem occurred
                    print("[" + constants.R + "!" + constants.W + "] " +
                          output + name)

        return local_templates

    def add_user_templates(self):
        # type: () -> None
        """Add all the user templates to the database."""
        user_templates = self.find_user_templates()

        for template in user_templates:
            # create a template object and add it to the database
            local_template = PhishingTemplate(template)
            self.templates[template] = local_template

    def on_exit(self):
        # type: () -> None
        """Delete any extra files on exit."""
        for templ_obj in self.templates.values():
            templ_obj.remove_extra_files()
