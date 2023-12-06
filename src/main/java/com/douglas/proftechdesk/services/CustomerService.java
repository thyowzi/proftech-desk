package com.douglas.proftechdesk.services;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.douglas.proftechdesk.domain.Customer;
import com.douglas.proftechdesk.domain.dtos.CustomerDTO;
import com.douglas.proftechdesk.repositories.CustomerRepository;
import com.douglas.proftechdesk.repositories.PersonRepository;
import com.douglas.proftechdesk.services.exceptions.DataIntegrityViolationException;
import com.douglas.proftechdesk.services.exceptions.ObjectNotFoundException;

import jakarta.validation.Valid;

@Service
public class CustomerService {

	@Autowired
	private CustomerRepository customerRepository;

	@Autowired
	private PersonRepository personRepository;

	@Autowired
	private BCryptPasswordEncoder encoder;

	public Customer findById(Integer id) {
		Optional<Customer> obj = customerRepository.findById(id);
		return obj.orElseThrow(() -> new ObjectNotFoundException("Object not found with ID: " + id));
	}

	public List<Customer> findAll() {
		return customerRepository.findAll();
	}

	public Customer create(CustomerDTO objectDTO) {
		objectDTO.setId(null);
		objectDTO.setPassword(encoder.encode(objectDTO.getPassword()));
		validationCpfAndEmail(objectDTO);
		Customer newObj = new Customer(objectDTO);
		return customerRepository.save(newObj);
	}

	public Customer update(Integer id, @Valid CustomerDTO objDTO){
	    Customer oldObj = findById(id);

	    if (!oldObj.getCpf().equals(objDTO.getCpf())) {
	      boolean cpfExists = personRepository.existsByCpf(objDTO.getCpf());
	      if (cpfExists) {
	        throw new DataIntegrityViolationException("CPF already registered on system!");
	      }
	    }

	    if (!oldObj.getEmail().equals(objDTO.getEmail())) {
	      boolean emailExists = personRepository.existsByEmail(objDTO.getEmail());
	      if (emailExists) {
	        throw new DataIntegrityViolationException("E-mail already registered on system!");
	      }
	    }

	    if(!objDTO.getPassword().equals(oldObj.getPassword())){
	      oldObj.setPassword(encoder.encode(objDTO.getPassword()));
	    }

	    oldObj.setName(objDTO.getName());
	    oldObj.setCpf(objDTO.getCpf());
	    oldObj.setEmail(objDTO.getEmail());

	    return customerRepository.save(oldObj);
	  }

	public void delete(Integer id) {
		Customer obj = findById(id);
		if (obj.getTickets().size() > 0) {
			throw new DataIntegrityViolationException("Customer has a service order and cannot be deleted!");
		}
		customerRepository.deleteById(id);
	}

	private void validationCpfAndEmail(CustomerDTO objDTO) {
		boolean cpf = personRepository.existsByCpf(objDTO.getCpf());
		if (cpf) {
			throw new DataIntegrityViolationException("CPF already registered in the system!");
		}

		boolean email = personRepository.existsByEmail(objDTO.getEmail());
		if (email) {
			throw new DataIntegrityViolationException("E-Mail already registered in the system!");
		}
	}
}
