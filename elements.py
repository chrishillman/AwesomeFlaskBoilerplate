def NavBar(links):
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