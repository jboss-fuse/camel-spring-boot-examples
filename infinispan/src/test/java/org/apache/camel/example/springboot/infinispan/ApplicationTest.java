package org.apache.camel.example.springboot.infinispan;

import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;
import org.apache.camel.CamelContext;
import org.apache.camel.EndpointInject;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.component.infinispan.InfinispanConstants;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.test.spring.junit5.CamelSpringBootTest;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.OutputFrame;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.io.File;
import java.nio.file.Path;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

@CamelSpringBootTest
@SpringBootTest(classes = Application.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
final class ApplicationTest {

	private static final Logger LOG = LoggerFactory.getLogger(ApplicationTest.class);

	private static final String CONTAINER_IMAGE = "quay.io/infinispan/server:15.1.5.Final";

	private static GenericContainer<?> container;

	@Autowired
	private ProducerTemplate producerTemplate;

	@Autowired
	private CamelContext camelContext;

	@EndpointInject("mock:result")
	private MockEndpoint putMockEndpoint;

	@EndpointInject("mock:result-read")
	private MockEndpoint getMockEndpoint;

	private static String host = "localhost";

	private static Integer port = 11222;

	private static String name = "infinispan";

	private static String username = "admin";

	private static String password = "password";

	private ApplicationTest() {
	}

	@BeforeAll
	public static void initContainer() {
		LOG.info("start infinispan docker container");
		final Consumer<CreateContainerCmd> cmd = e -> {
			e.getHostConfig().withPortBindings(new PortBinding(Ports.Binding.bindPort(port),
					new ExposedPort(port)));

		};
		final Logger containerLog = LoggerFactory.getLogger("container." + name);
		final Consumer<OutputFrame> logConsumer = new Slf4jLogConsumer(containerLog);

		container = new GenericContainer<>(CONTAINER_IMAGE).withNetworkAliases(name)
				.withEnv("USER", username).withEnv("PASS", password)
				.withLogConsumer(logConsumer)
				.withClasspathResourceMapping("infinispan.xml", "/user-config/infinispan.xml",
						BindMode.READ_ONLY)
				.withCommand("-c", "/user-config/infinispan.xml").withExposedPorts(port)
				.withCreateContainerCmdModifier(cmd).waitingFor(Wait.forListeningPort())
				.waitingFor(Wait.forLogMessage(".*Infinispan.*Server.*started.*", 1));
		container.start();
	}

	@AfterAll
	public static void stopContainer() {
		container.stop();
	}

	@AfterEach
	public void resetMocks() {
		putMockEndpoint.reset();
		getMockEndpoint.reset();
	}

	@Test
	public void shouldPopulateCache() throws Exception {

		final String randomPart = UUID.randomUUID().toString().substring(0, 5);
		final String key = "key-" + randomPart;
		final String body = "random string " + randomPart;

		putMockEndpoint.expectedMessageCount(1);
		producerTemplate.sendBodyAndHeader("direct:test", body, "id", key);
		putMockEndpoint.assertIsSatisfied();
		Assertions.assertEquals(key, putMockEndpoint.getExchanges().get(0).getIn().getHeader(InfinispanConstants.KEY));
		Assertions.assertEquals(body, putMockEndpoint.getExchanges().get(0).getIn().getHeader(InfinispanConstants.VALUE));

		Awaitility.await("wait for the added cache item")
			.atMost(Duration.of(5, ChronoUnit.SECONDS))
			.pollInterval(Duration.of(1, ChronoUnit.SECONDS))
					.untilAsserted(() -> org.assertj.core.api.Assertions.assertThat(Path.of("target/test.log"))
							.content()
							.containsPattern("Received headers: .* CamelInfinispanKey=" + key)
							.contains("Received body: " + body));

		getMockEndpoint.expectedMessageCount(1);
		producerTemplate.sendBodyAndHeader("direct:test-read", null, InfinispanConstants.KEY, key);
		getMockEndpoint.assertIsSatisfied();
		Assertions.assertEquals(body, getMockEndpoint.getExchanges().get(0).getIn().getBody());
	}
}
