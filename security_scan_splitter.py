import logging
import itertools
import os.path
import datetime

import click
import pandas
import jinja2
import markdown
import weasyprint
import openstack


logger = logging.getLogger(__name__)


def get_servers():
    """
    Gets the servers in the cloud indexed by external IP.

    Servers without an external IP are excluded, as they are not relevant.
    """
    conn = openstack.connect(cloud = 'jasmin-admin')
    # Get a map of id -> project name
    projects = {
        project.id: project.name
        for project in conn.identity.projects()
    }
    # Get the server name and IP for all the servers in the cloud, grouped by project
    servers = {}
    for server in conn.compute.servers(all_tenants = True):
        try:
            external_ip = next(
                a['addr']
                for a in itertools.chain.from_iterable(server.addresses.values())
                if a['OS-EXT-IPS:type'] == 'floating'
            )
        except StopIteration:
            continue
        servers[external_ip] = dict(
            name = server.name,
            project = projects[server.project_id],
            external_ip = external_ip
        )
    return servers


def get_vulnerabilities(xlsx_file):
    """
    Returns an iterable of vulnerabilities in the given Excel file.
    """
    return map(
        lambda v: dict(
            server_ip = v[10],
            title = v[3],
            description = v[1],
            impact = v[0],
            probability = v[2],
            cvss_score = v[4],
            cvss_vector = v[7],
            remediation = v[11],
        ),
        pandas.read_excel(xlsx_file).fillna('').itertuples(index = False)
    )


# Pre-load the project report template
HERE = os.path.abspath(os.path.dirname(__file__))
ENVIRONMENT = jinja2.Environment()
ENVIRONMENT.filters['markdown'] = lambda text: jinja2.Markup(markdown.markdown(text))
with open(os.path.join(HERE, 'project_report.html')) as f:
    TEMPLATE = ENVIRONMENT.from_string(f.read())

def render_project_pdf(project, vulnerabilities, output_path):
    """
    Renders a PDF report at the given path containing the given
    vulnerabilities for the given project.
    """
    logging.info("  %s", project)
    html = TEMPLATE.render(
        project = project,
        vulnerabilities = vulnerabilities,
        current_date = datetime.date.today()
    )
    weasyprint.HTML(string = html).write_pdf(output_path)


def make_project_reports(scan_file, output_dir):
    """
    Split the given security scan into project-specific PDFs.
    """
    logging.info("Fetching server information from OpenStack...")
    servers = get_servers()
    # Group the vulnerabilities by project, and add server name to each
    logging.info("Parsing vulnerabilities file...")
    vulnerabilities = {}
    for v in get_vulnerabilities(scan_file):
        # Assume that any missing IPs belong to machines that have been
        # deleted, and so are no longer relevant
        try:
            server = servers[v['server_ip']]
        except KeyError:
            continue
        vulnerabilities  \
            .setdefault(server['project'], list())  \
            .append(dict(v, server_name = server['name']))
    logging.info("Rendering project reports...")
    # Produce a report for each project
    for project, project_vulnerabilities in vulnerabilities.items():
        output_path = os.path.join(output_dir, project + '.pdf')
        render_project_pdf(project, project_vulnerabilities, output_path)


@click.command()
@click.option(
    '-o', '--output-dir',
    type = click.Path(writable = True, file_okay = False, resolve_path = True),
    help = 'Directory in which to place project reports'
)
@click.argument(
    'scan_file',
    type = click.Path(readable = True, dir_okay = False, resolve_path = True)
)
def main(scan_file, output_dir):
    """
    Splits the given JASMIN Unmanaged Cloud security scan to produce
    a PDF for each affected project.
    """
    logging.basicConfig(level = logging.INFO, format = "%(message)s")
    logging.getLogger('weasyprint').setLevel(logging.ERROR)
    if output_dir is None:
        output_dir = os.path.dirname(scan_file)
    logging.info("Using source file: %s", scan_file)
    logging.info("Using output directory: %s", output_dir)
    make_project_reports(scan_file, output_dir)
