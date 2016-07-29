# Copyright (C) 2016 GRNET S.A.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from paste import deploy
from snfOCCI.config import PASTEDEPLOY
import logging
from paste import httpserver

LOG = logging.getLogger(__name__)

# Setup a server for testing
application = deploy.loadapp('config:{0}'.format(PASTEDEPLOY))
httpserver.serve(application, '127.0.0.1', '8080')
