package com.madan.test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.dialogflow.v2.Intent;
import com.google.cloud.dialogflow.v2.IntentsClient;
import com.google.cloud.dialogflow.v2.ProjectAgentName;

@SpringBootApplication
public class TestDfApplication {

	public static void main(String[] args) throws FileNotFoundException, IOException {
		//SpringApplication.run(TestDfApplication.class, args);
		
		
		/*Storage storage = StorageOptions.newBuilder()
			    .setCredentials(ServiceAccountCredentials.fromStream(new FileInputStream("/PersonalData/dialogflow/testagent-7edbe-519d83b04a46.json")))
			    .build()
			    .getService();*/
		/*Storage storage = StorageOptions.getDefaultInstance().getService();
		System.out.println(storage);*/
		
		GoogleCredentials credentials = GoogleCredentials.getApplicationDefault();
		//GoogleCredentials credentials = GoogleCredentials.fromStream(new FileInputStream("/PersonalData/dialogflow/testagent-7edbe-519d83b04a46.json"));
		
		credentials.refreshIfExpired();
		AccessToken token = credentials.getAccessToken();
		
		System.out.println(token.getTokenValue());
		
		try (IntentsClient intentsClient = IntentsClient.create()) {
			   ProjectAgentName parent = ProjectAgentName.of("dialogmanager-agent-v2");
			   for (Intent element : intentsClient.listIntents(parent).iterateAll()) {
			     System.out.println(element.getDisplayName());
			   }
			 }
	}
}
