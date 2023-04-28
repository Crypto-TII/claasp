
# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************


from jinja2 import Environment, FileSystemLoader


class TemplateManager:
    """
    Controls the construction process.

    TemplateManager has a builder associated with him. TemplateManager then
    delegates building of the smaller parts to the builder and
    assembles them together.

    """

    __builder = None

    def set_builder(self, builder):
        self.__builder = builder

    # The algorithm for assembling a template
    def get_template(self):
        template = Template()

        body = self.__builder.get_body()
        template.set_body(body)

        footer = self.__builder.get_footer()
        template.set_footer(footer)

        header = self.__builder.get_header()
        template.set_header(header)

        return template


class Template:

    def __init__(self):
        self._j2_env = Environment(loader=FileSystemLoader('claasp/utils/tii_reports'),
                                   trim_blocks=True, autoescape=True)
        self.__header = None
        self.__footer = None
        self.__body = None

    def set_body(self, body):
        self.__body = body

    def set_header(self, header):
        self.__header = header

    def set_footer(self, footer):
        self.__footer = footer

    def render_template(self, rule_data_):
        return self._j2_env.get_template(rule_data_['template_path']).render(header=self.__header.content,
                                                                             body=self.__body.content,
                                                                             footer=self.__footer.content,
                                                                             rule_data=rule_data_)


class Builder(object):
    """
    Creates various parts of a html/txt.

    This class is responsible for constructing all the parts for a html/txt.

    """

    def get_header(self): pass
    def get_footer(self): pass
    def get_body(self): pass


class LatexBuilder(Builder):
    """
    Concrete Builder implementation.

    This class builds parts for latex.

    """

    def __init__(self, data):
        self.data = data

    def get_header(self):
        header = Header()
        header.content = 'TII - Latex - Report'

        return header

    def get_footer(self):
        footer = Footer()
        footer.content = ''

        return footer

    def get_body(self):
        body = Body()
        body.content = self.data

        return body


class CSVBuilder(Builder):
    """
    Concrete Builder implementation.

    This class builds parts for the CSV report.

    """

    def __init__(self, data):
        self.data = data

    def get_header(self):
        header = Header()
        header.content = 'TII - CSV - Report'

        return header

    def get_footer(self):
        footer = Footer()
        footer.content = ''

        return footer

    def get_body(self):
        body = Body()
        body.content = self.data

        return body


# Template parts
class Header:
    logo = None
    content = None


class Footer:
    content = None


class Body:
    content = None


if __name__ == "__main__":
    main()
