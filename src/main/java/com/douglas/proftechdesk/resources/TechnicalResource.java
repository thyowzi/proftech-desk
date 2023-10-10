package com.douglas.proftechdesk.resources;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.douglas.proftechdesk.domain.Technical;
import com.douglas.proftechdesk.domain.dtos.TechnicalDTO;
import com.douglas.proftechdesk.services.TechnicalService;

@RestController
@RequestMapping(value = "/technicals")
public class TechnicalResource {

	@Autowired
	private TechnicalService technicalService;

	@GetMapping(value = "/{id}")
	public ResponseEntity<TechnicalDTO> findById(@PathVariable Integer id) {
		Technical object = technicalService.findById(id);
		return ResponseEntity.ok().body(new TechnicalDTO(object));
	}

	@GetMapping
	public ResponseEntity<List<TechnicalDTO>> findAll() {
		List<Technical> list = technicalService.findAll();
		List<TechnicalDTO> listDTO = list.stream().map(TechnicalDTO::new).collect(Collectors.toList());
		return ResponseEntity.ok().body(listDTO);
	}
}
