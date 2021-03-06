<?xml version="1.0" encoding="utf-8" ?>
<file>
<properties><descriptions><description><value>admin</value><key>author</key></description><description><value>20/10/2014 18:55:30</value><key>creation date</key></description><description><value>Just a basic sample.</value><key>summary</key></description><description><value>None.</value><key>prerequisites</key></description><description><value><comments /></value><key>comments</key></description><description><value>myplugins</value><key>libraries</key></description><description><value>myplugins</value><key>adapters</key></description><description><value>Writing</value><key>state</key></description><description><value>REQ_01</value><key>requirement</key></description></descriptions><inputs-parameters><parameter><color /><description /><type>bool</type><name>DEBUG</name><value>False</value><scope>local</scope></parameter><parameter><color /><description /><type>float</type><name>TIMEOUT</name><value>1.0</value><scope>local</scope></parameter></inputs-parameters><agents><agent><description /><type /><name>AGENT</name><value>agent-socket01</value></agent></agents><probes><probe><active>False</active><args /><name>probe01</name><type>default</type></probe></probes><outputs-parameters><parameter><color /><description /><type>float</type><name>TIMEOUT</name><value>1.0</value><scope>local</scope></parameter></outputs-parameters></properties>
<testdefinition><![CDATA[
class ERR_OP_001(TestCase):

	def description(self):
		# testcase description
		self.setPurpose(purpose="Testcase sample")

		# steps description
		self.step1 = self.addStep(expected="result expected", description="step description", summary="step sample")


	def prepare(self):
		# adapters and libraries
		pass


	def cleanup(self, aborted):
		pass


	def definition(self):
		# starting initial step
		self.step1.start()
		self.step1.setPassed(actual="success")
		
		op = TestOperators.Contains(needle=["A", "B"], AND=False, OR=False)
		ret= op.seekIn(haystack="3")

class ERR_OP_002(TestCase):

	def description(self):
		# testcase description
		self.setPurpose(purpose="Testcase sample")

		# steps description
		self.step1 = self.addStep(expected="result expected", description="step description", summary="step sample")


	def prepare(self):
		# adapters and libraries
		pass


	def cleanup(self, aborted):
		pass


	def definition(self):
		# starting initial step
		self.step1.start()
		self.step1.setPassed(actual="success")
		
		op = TestOperators.NotContains(needle=["A", "B"], AND=False, OR=False)
		ret= op.seekIn(haystack="3")
class ERR_OP_003(TestCase):

	def description(self):
		# testcase description
		self.setPurpose(purpose="Testcase sample")

		# steps description
		self.step1 = self.addStep(expected="result expected", description="step description", summary="step sample")


	def prepare(self):
		# adapters and libraries
		pass


	def cleanup(self, aborted):
		pass


	def definition(self):
		# starting initial step
		self.step1.start()
		self.step1.setPassed(actual="success")
		
		op = TestOperators.GreaterThan(x="34a")
		ret= op.comp(y="3")
class ERR_OP_004(TestCase):

	def description(self):
		# testcase description
		self.setPurpose(purpose="Testcase sample")

		# steps description
		self.step1 = self.addStep(expected="result expected", description="step description", summary="step sample")


	def prepare(self):
		# adapters and libraries
		pass


	def cleanup(self, aborted):
		pass


	def definition(self):
		# starting initial step
		self.step1.start()
		self.step1.setPassed(actual="success")
		
		op = TestOperators.GreaterThan(x="34")
		ret= op.comp(y="a")
class ERR_OP_005(TestCase):

	def description(self):
		# testcase description
		self.setPurpose(purpose="Testcase sample")

		# steps description
		self.step1 = self.addStep(expected="result expected", description="step description", summary="step sample")


	def prepare(self):
		# adapters and libraries
		pass


	def cleanup(self, aborted):
		pass


	def definition(self):
		# starting initial step
		self.step1.start()
		self.step1.setPassed(actual="success")
		
		op = TestOperators.LowerThan(x="34a")
		ret= op.comp(y="3")
class ERR_OP_006(TestCase):

	def description(self):
		# testcase description
		self.setPurpose(purpose="Testcase sample")

		# steps description
		self.step1 = self.addStep(expected="result expected", description="step description", summary="step sample")


	def prepare(self):
		# adapters and libraries
		pass


	def cleanup(self, aborted):
		pass


	def definition(self):
		# starting initial step
		self.step1.start()
		self.step1.setPassed(actual="success")
		
		op = TestOperators.LowerThan(x="34")
		ret= op.comp(y="a")]]></testdefinition>
<testexecution><![CDATA[
ERR_OP_001(suffix=None).execute()
ERR_OP_002(suffix=None).execute()
ERR_OP_003(suffix=None).execute()
ERR_OP_004(suffix=None).execute()
ERR_OP_005(suffix=None).execute()
ERR_OP_006(suffix=None).execute()]]></testexecution>
<testdevelopment>1413824130.07</testdevelopment>
</file>