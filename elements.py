
def PopulateSelect(formfield, value):
    formfield.data = value
    for field in formfield:
        if field.data == value:
            field.checked = True
    return formfield

def NavBar(links):
    """
    NavBar function
    :param links: list of link dictionaries, url: url for link, display: user word for link
    :return:
    """
    output = """
<nav>
    <div class="nav-wrapper row bgMAROON" id="nav">
      <div class="col s10 nav">
        """
    tail = """
      </div>
        <div class="col s2 nav">
            <a href="/logout.html" class="btn-large bgMAROON fgSNOW">Logout</a>
        </div>
    </div>
</nav>
"""
    for link in links:
        output += f"""<a href="{link["url"]}" class="breadcrumb">{link["display"]}</a>"""
    output += tail
    return output

def ConfirmBar(links, message):
    """
    ConfirmBar function
    :param links: list of link dictionaries, url: url for link, display: user action for link, color: color name/value/class
    :param message: String describing the successful action
    :return:
    """
    output = f"""
    <div class="row textcontain ">
    <div class="input-field col s12 bgLIGHTGREEN">
    <p class="flow-text center">
    { message } </p> """
    tail = """
    </div>
    </div>
    """
    for link in links:
        output += f"""<a href="{ link['url'] }" class="btn-large longbutton waves-light {link['color']}" >{ link['display'] }</a>"""
    output += tail
    return output