@Library('jenkins-shared-library@master') _
import dev.techyon.jenkins.pipelines.application.ApplicationPipelineConfig

ApplicationPipelineConfig config = new ApplicationPipelineConfig();
config.setShouldSkipDeployment(true);
// config.setUnitTestCommand("gradle test");

go_pipeline(config)
