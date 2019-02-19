package com.danoff.rest.web;

import java.util.ArrayList;
import java.util.List;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.danoff.rest.dto.Greeting;
import com.danoff.rest.service.IdGenerator;

@RestController
@RequestMapping(value = "/greetings")
public class SimpleRestController {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(SimpleRestController.class);
	
	private static final List<Greeting> storedGreetings = new ArrayList<>();
	
	private final IdGenerator generator;
	
	@Autowired
	public SimpleRestController(IdGenerator generator) {
		this.generator = generator;
	}
	
	@RequestMapping(method = RequestMethod.GET)
    @ResponseBody
    @ResponseStatus(value = HttpStatus.OK)
    public List<Greeting> getAllGreetings() {
    	LOGGER.debug("Received request to getAllGreetings() resource");
        return storedGreetings;
    }
	
	@RequestMapping(method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_UTF8_VALUE, consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
	@ResponseStatus(value = HttpStatus.CREATED)
	public Greeting createResources(@Valid @RequestBody Greeting dto) {
		LOGGER.debug("Received request to createResources() with params dto={}", dto);
        if(dto == null) {
        	throw new IllegalArgumentException("Payload is empty");
        }
        
        if(dto.getId() != null) {
        	throw new IllegalArgumentException("Greeting ID must not be populated");
        }
		
        dto.setId(generator.generateId());
        storedGreetings.add(dto);
        
        return dto;
	}
}
